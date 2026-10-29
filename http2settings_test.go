package eidolon_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// h2Preface returns the SETTINGS, the WINDOW_UPDATE increments on the
// connection, and the pseudo-headers and priority of the first request
// that c sent to a new lab server, with the header given.
func h2Preface(t *testing.T, header http.Header, opts ...eidolon.Option) ([]lab.Setting, []uint32, []string, *lab.Priority) {
	t.Helper()
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	c := newClient(t, srv, opts...)
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	frames, err := srv.NextConn(t).H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	var settings []lab.Setting
	var updates []uint32
	var pseudo []string
	var prio *lab.Priority
	for _, f := range frames {
		switch {
		case f.Type == "SETTINGS" && f.Flags&0x1 == 0 && settings == nil:
			settings = append([]lab.Setting{}, f.Settings...)
		case f.Type == "WINDOW_UPDATE" && f.StreamID == 0:
			updates = append(updates, f.Increment)
		case f.Type == "HEADERS" && pseudo == nil:
			prio = f.Priority
			for _, h := range f.Headers {
				if h.Name[0] == ':' {
					pseudo = append(pseudo, h.Name)
				}
			}
		}
	}
	return settings, updates, pseudo, prio
}

// A new HTTP/2 connection starts as Chrome 156 does (A10), unless
// WithHTTP2Settings says otherwise; the pseudo-headers follow Chrome
// unless the request or the client orders them, and the HEADERS priority
// follows Chromium unless WithHTTP2Settings leaves it out.
func TestHTTP2Preface(t *testing.T) {
	chrome := []lab.Setting{{ID: 1, Val: 65536}, {ID: 2, Val: 0}, {ID: 4, Val: 6291456}, {ID: 6, Val: 262144}}
	masp := []string{":method", ":authority", ":scheme", ":path"}
	u3 := &lab.Priority{Exclusive: true, Weight: 146}
	for _, tt := range []struct {
		name     string
		header   http.Header
		opts     []eidolon.Option
		settings []lab.Setting
		updates  []uint32
		pseudo   []string
		prio     *lab.Priority
	}{
		{name: "default", settings: chrome, updates: []uint32{15663105}, pseudo: masp, prio: u3},
		{
			name: "default with priority u=0", header: http.Header{"Priority": {"u=0, i"}},
			settings: chrome, updates: []uint32{15663105}, pseudo: masp, prio: &lab.Priority{Exclusive: true, Weight: 255},
		},
		{
			name: "custom with Chromium priority", header: http.Header{"Priority": {"u=2"}},
			opts:     []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{Priority: eidolon.HTTP2PriorityChromium})},
			settings: []lab.Setting{}, pseudo: masp, prio: &lab.Priority{Exclusive: true, Weight: 182},
		},
		{
			name: "custom",
			opts: []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{Settings: []eidolon.HTTP2Setting{
				{ID: eidolon.HTTP2SettingMaxConcurrentStreams, Value: 100},
				{ID: eidolon.HTTP2SettingInitialWindowSize, Value: 131072},
				{ID: 0x0a0a, Value: 7},
			}})},
			settings: []lab.Setting{{ID: 3, Val: 100}, {ID: 4, Val: 131072}, {ID: 0x0a0a, Val: 7}},
			pseudo:   masp,
		},
		{
			name:     "client order first",
			opts:     []eidolon.Option{eidolon.WithDefaultOrder(eidolon.Order{Pseudo: []string{":path", ":scheme"}})},
			settings: chrome, updates: []uint32{15663105},
			pseudo: []string{":path", ":scheme", ":method", ":authority"}, prio: u3,
		},
		{
			name:     "request order first",
			header:   http.Header{eidolon.PHeaderOrderKey: {":method", ":scheme", ":path", ":authority"}},
			settings: chrome, updates: []uint32{15663105},
			pseudo: []string{":method", ":scheme", ":path", ":authority"}, prio: u3,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			settings, updates, pseudo, prio := h2Preface(t, tt.header, tt.opts...)
			if !slices.Equal(settings, tt.settings) {
				t.Errorf("SETTINGS %v, want %v", settings, tt.settings)
			}
			if !slices.Equal(updates, tt.updates) {
				t.Errorf("WINDOW_UPDATE %v, want %v", updates, tt.updates)
			}
			if !slices.Equal(pseudo, tt.pseudo) {
				t.Errorf("pseudo-headers %v, want %v", pseudo, tt.pseudo)
			}
			if (prio == nil) != (tt.prio == nil) || prio != nil && *prio != *tt.prio {
				t.Errorf("priority %+v, want %+v", prio, tt.prio)
			}
		})
	}
}

// A request body goes in DATA frames of 16375 bytes by default, as
// Chrome's, below the 1 MiB MAX_FRAME_SIZE of the lab server; without
// MaxDataFrameSize, as large as the server allows. A GET goes first, so
// the server's SETTINGS are in force for the body.
func TestHTTP2DataFrames(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts []eidolon.Option
		want []uint32
	}{
		{"default", nil, []uint32{16375, 16375, 16375, 16375, 36}},
		{"custom", []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{MaxDataFrameSize: 20000})}, []uint32{20000, 20000, 20000, 5536}},
		{"none", []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{})}, []uint32{65536}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
			})})
			c := newClient(t, srv, tt.opts...)
			for _, body := range []io.Reader{nil, bytes.NewReader(make([]byte, 65536))} {
				method := http.MethodGet
				if body != nil {
					method = http.MethodPost
				}
				req, _ := http.NewRequest(method, "https://example.com/", body)
				resp, err := c.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			frames, err := srv.NextConn(t).H2Frames()
			if err != nil {
				t.Fatal(err)
			}
			var got []uint32
			for _, f := range frames {
				if f.Type == "DATA" {
					got = append(got, f.Length)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("DATA frames %v, want %v", got, tt.want)
			}
		})
	}
}

// The header fields are encoded as Chromium by default: a second request
// to the same path sends :path again as a literal without indexing, where
// HTTP2HPACKGo indexes it.
func TestHTTP2HPACK(t *testing.T) {
	literal := []byte{0x04, 0x02, '/', 'a'}
	for _, tt := range []struct {
		name    string
		opts    []eidolon.Option
		literal bool
	}{
		{"default", nil, true},
		{"chromium", []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{HPACK: eidolon.HTTP2HPACKChromium})}, true},
		{"go", []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{})}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
			c := newClient(t, srv, tt.opts...)
			for range 2 {
				resp, err := c.Get("https://example.com/a")
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			frames, err := srv.NextConn(t).H2Frames()
			if err != nil {
				t.Fatal(err)
			}
			var blocks [][]byte
			for _, f := range frames {
				if f.Type == "HEADERS" {
					blocks = append(blocks, f.Block)
				}
			}
			if len(blocks) != 2 {
				t.Fatalf("%d HEADERS, want 2", len(blocks))
			}
			if got := bytes.Contains(blocks[1], literal); got != tt.literal {
				t.Errorf("second block %x: :path literal %v, want %v", blocks[1], got, tt.literal)
			}
		})
	}
}

// After PrefacePing without a read, the next request sends a PING with
// payload 1 right after its HEADERS; without PrefacePing, none.
func TestHTTP2PrefacePing(t *testing.T) {
	for _, tt := range []struct {
		name string
		ping time.Duration
		want []string
	}{
		{"ping", 200 * time.Millisecond, []string{"HEADERS", "HEADERS", "PING"}},
		{"none", 0, []string{"HEADERS", "HEADERS"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
			c := newClient(t, srv, eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{PrefacePing: tt.ping}))
			for i := range 2 {
				if i == 1 {
					time.Sleep(300 * time.Millisecond)
				}
				resp, err := c.Get("https://example.com/")
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			frames, err := srv.NextConn(t).H2Frames()
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range frames {
				if f.Type == "HEADERS" || f.Type == "PING" && f.Flags&0x1 == 0 {
					got = append(got, f.Type)
					if f.Type == "PING" && f.Ping != [8]byte{7: 1} {
						t.Errorf("PING payload %x, want 1", f.Ping)
					}
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("frames %v, want %v", got, tt.want)
			}
		})
	}
}

// The receive windows go back as Chromium by default: a response of 1 MiB
// is read without any WINDOW_UPDATE after the first, since its windows
// are of 6 and 15 MiB; with windows of 64 KiB, each update gives back more
// than half of one. HTTP2WindowUpdateGo gives them back as they are read.
func TestHTTP2WindowUpdate(t *testing.T) {
	small := eidolon.HTTP2Settings{
		Settings:     []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingInitialWindowSize, Value: 65536}},
		WindowUpdate: eidolon.HTTP2WindowUpdateChromium,
	}
	for _, tt := range []struct {
		name  string
		opts  []eidolon.Option
		first bool // a WINDOW_UPDATE follows SETTINGS
		ok    func(updates []uint32) bool
	}{
		{"default", nil, true, func(u []uint32) bool { return len(u) == 0 }},
		{"chromium", []eidolon.Option{eidolon.WithHTTP2Settings(small)}, false, func(u []uint32) bool {
			return len(u) > 0 && !slices.ContainsFunc(u, func(n uint32) bool { return n <= 32767 })
		}},
		{"go", []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{})}, false, func(u []uint32) bool {
			return len(u) > 0
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(make([]byte, 1<<20))
			})})
			c := newClient(t, srv, tt.opts...)
			resp, err := c.Get("https://example.com/")
			if err != nil {
				t.Fatal(err)
			}
			if n, _ := io.Copy(io.Discard, resp.Body); n != 1<<20 {
				t.Fatalf("read %d", n)
			}
			resp.Body.Close()
			frames, err := srv.NextConn(t).H2Frames()
			if err != nil {
				t.Fatal(err)
			}
			var updates []uint32
			for _, f := range frames {
				if f.Type == "WINDOW_UPDATE" {
					updates = append(updates, f.Increment)
				}
			}
			if tt.first {
				updates = updates[1:]
			}
			if !tt.ok(updates) {
				t.Errorf("WINDOW_UPDATE %v", updates)
			}
		})
	}
}

// A request cancelled before its response sends RST_STREAM alone by
// default, as Chrome; without CancelWithoutPing, a PING goes with it. A
// GET goes first, so nothing is read after the cancelled HEADERS.
func TestHTTP2CancelWithoutPing(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts []eidolon.Option
		want []string
	}{
		{"default", nil, []string{"HEADERS", "HEADERS", "RST_STREAM"}},
		{"set", []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{CancelWithoutPing: true})}, []string{"HEADERS", "HEADERS", "RST_STREAM"}},
		{"go", []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{})}, []string{"HEADERS", "HEADERS", "RST_STREAM", "PING"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/block" {
					<-r.Context().Done()
				}
			})})
			c := newClient(t, srv, tt.opts...)
			resp, err := c.Get("https://example.com/")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/block", nil)
			if _, err := c.Do(req); err == nil {
				t.Fatal("cancelled request answered")
			}
			conn := srv.NextConn(t)
			var got []string
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				frames, err := conn.H2Frames()
				if err != nil {
					t.Fatal(err)
				}
				got = got[:0]
				for _, f := range frames {
					if f.Type == "HEADERS" || f.Type == "RST_STREAM" || f.Type == "PING" && f.Flags&0x1 == 0 {
						got = append(got, f.Type)
					}
				}
				if slices.Equal(got, tt.want) {
					return
				}
			}
			t.Errorf("frames %v, want %v", got, tt.want)
		})
	}
}

// A priority tree as Firefox up to version 88 built it, with one
// dependency made exclusive to check the flag: PRIORITY frames after
// SETTINGS and WINDOW_UPDATE, and the requests from stream 15 with a fixed
// priority. The frames given are copied when the option is made.
func TestHTTP2PriorityTree(t *testing.T) {
	tree := []eidolon.HTTP2PriorityFrame{
		{3, eidolon.HTTP2PriorityParam{Weight: 200}},
		{5, eidolon.HTTP2PriorityParam{Weight: 100}},
		{7, eidolon.HTTP2PriorityParam{}},
		{9, eidolon.HTTP2PriorityParam{StreamDep: 7, Exclusive: true}},
		{11, eidolon.HTTP2PriorityParam{StreamDep: 3}},
		{13, eidolon.HTTP2PriorityParam{Weight: 240}},
	}
	header := eidolon.HTTP2PriorityParam{StreamDep: 13, Weight: 41}
	opt := eidolon.WithHTTP2Settings(eidolon.HTTP2Settings{
		Settings:               []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingInitialWindowSize, Value: 131072}},
		ConnectionWindowUpdate: 12517377,
		Priority:               eidolon.HTTP2PriorityFixed,
		HeaderPriority:         header,
		PriorityFrames:         tree,
		FirstStreamID:          15,
	})
	tree[0].Weight = 1
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	c := newClient(t, srv, opt)
	for range 2 {
		resp, err := c.Get("https://example.com/")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	frames, err := srv.NextConn(t).H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range frames {
		switch f.Type {
		case "WINDOW_UPDATE":
			got = append(got, fmt.Sprint(f.Type, " ", f.Increment))
		case "PRIORITY", "HEADERS":
			got = append(got, fmt.Sprintf("%s %d %+v", f.Type, f.StreamID, *f.Priority))
		}
	}
	want := []string{"WINDOW_UPDATE 12517377"}
	tree[0].Weight = 200
	for _, p := range tree {
		want = append(want, fmt.Sprintf("PRIORITY %d %+v", p.StreamID, lab.Priority{StreamDep: p.StreamDep, Exclusive: p.Exclusive, Weight: p.Weight}))
	}
	h := lab.Priority{StreamDep: header.StreamDep, Weight: header.Weight}
	want = append(want, fmt.Sprintf("HEADERS 15 %+v", h), fmt.Sprintf("HEADERS 17 %+v", h))
	if !slices.Equal(got, want) {
		t.Errorf("frames\n%q\nwant\n%q", got, want)
	}
}

// Settings the client cannot honor are refused by New.
func TestWithHTTP2SettingsInvalid(t *testing.T) {
	for _, s := range []eidolon.HTTP2Settings{
		{Settings: []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingEnablePush, Value: 1}}},
		{Settings: []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingMaxFrameSize, Value: 1}}},
		{Settings: []eidolon.HTTP2Setting{{ID: 4, Value: 1}, {ID: 4, Value: 2}}},
		{ConnectionWindowUpdate: 1 << 31},
		{Settings: []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingNoRFC7540Priorities, Value: 1}}, Priority: eidolon.HTTP2PriorityChromium},
		{Priority: 7},
		{HPACK: 7},
		{PrefacePing: -1},
		{WindowUpdate: 7},
		{Errors: 7},
		{ALPS: 7},
		{HeaderFraming: 2},
		{Priority: eidolon.HTTP2PriorityFixed},
		{HeaderPriority: eidolon.HTTP2PriorityParam{Weight: 41}},
		{
			Settings: []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingNoRFC7540Priorities, Value: 1}},
			Priority: eidolon.HTTP2PriorityFixed, HeaderPriority: eidolon.HTTP2PriorityParam{Weight: 41},
		},
		{
			Settings:       []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingNoRFC7540Priorities, Value: 1}},
			PriorityFrames: []eidolon.HTTP2PriorityFrame{{StreamID: 3}},
		},
		{PriorityFrames: []eidolon.HTTP2PriorityFrame{{StreamID: 0, HTTP2PriorityParam: eidolon.HTTP2PriorityParam{StreamDep: 3}}}},
		{Priority: eidolon.HTTP2PriorityFixed, HeaderPriority: eidolon.HTTP2PriorityParam{StreamDep: 1 << 31}},
		{FirstStreamID: 2},
	} {
		if c, err := eidolon.New(eidolon.WithClientHello(chromeSpec), eidolon.WithHTTP2Settings(s)); !errors.Is(err, eidolon.ErrConfig) || c != nil {
			t.Errorf("New with %v = %v, %v; want ErrConfig", s, c, err)
		}
	}
}
