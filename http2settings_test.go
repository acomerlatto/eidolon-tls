package eidolon_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"slices"
	"testing"

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

// Settings the client cannot honor are refused by New.
func TestWithHTTP2SettingsInvalid(t *testing.T) {
	for _, s := range []eidolon.HTTP2Settings{
		{Settings: []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingEnablePush, Value: 1}}},
		{Settings: []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingMaxFrameSize, Value: 1}}},
		{Settings: []eidolon.HTTP2Setting{{ID: 4, Value: 1}, {ID: 4, Value: 2}}},
		{ConnectionWindowUpdate: 1 << 31},
		{Settings: []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingNoRFC7540Priorities, Value: 1}}, Priority: eidolon.HTTP2PriorityChromium},
		{Priority: 7},
	} {
		if c, err := eidolon.New(eidolon.WithClientHello(chromeSpec), eidolon.WithHTTP2Settings(s)); !errors.Is(err, eidolon.ErrConfig) || c != nil {
			t.Errorf("New with %v = %v, %v; want ErrConfig", s, c, err)
		}
	}
}
