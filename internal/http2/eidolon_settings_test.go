// SETTINGS and connection window given by the caller (patch 0019).

package http2

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/http2/hpack"
)

// prefaceSeen is what the client sent before its first request.
type prefaceSeen struct {
	settings []Setting
	updates  []uint32 // WINDOW_UPDATE increments on the connection
}

// settingsServer reads the preface of c, reports it, and answers the first
// request with respond, which writes frames on stream 1, then a PING. done
// is closed when the PING is acknowledged, so the client processed every
// frame respond wrote, or when the connection ends.
func settingsServer(c net.Conn, respond func(fr *Framer), done chan<- struct{}) <-chan prefaceSeen {
	seen := make(chan prefaceSeen, 1)
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		defer finish()
		defer c.Close()
		if _, err := io.ReadFull(c, make([]byte, len(ClientPreface))); err != nil {
			return
		}
		fr := NewFramer(c, c)
		// net.Pipe has no buffer: write from another goroutine, in order.
		writes := make(chan func(), 8)
		defer close(writes)
		go func() {
			for w := range writes {
				w()
			}
		}()
		writes <- func() { fr.WriteSettings() }
		var p prefaceSeen
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *SettingsFrame:
				if !f.IsAck() {
					f.ForeachSetting(func(s Setting) error { p.settings = append(p.settings, s); return nil })
					writes <- func() { fr.WriteSettingsAck() }
				}
			case *WindowUpdateFrame:
				if f.StreamID == 0 {
					p.updates = append(p.updates, f.Increment)
				}
			case *HeadersFrame:
				seen <- p
				writes <- func() { respond(fr); fr.WritePing(false, [8]byte{1}) }
			case *PingFrame:
				if f.IsAck() {
					finish()
				}
			}
		}
	}()
	return seen
}

// respondWith answers stream 1 with 200, the extra header fields and body
// in DATA frames of at most frame bytes, written without waiting for
// flow control. enc, if set, encodes the header block.
func respondWith(enc *hpack.Encoder, block *bytes.Buffer, extra []hpack.HeaderField, body []byte, frame int) func(*Framer) {
	return func(fr *Framer) {
		if enc == nil {
			block = new(bytes.Buffer)
			enc = hpack.NewEncoder(block)
		}
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		for _, f := range extra {
			enc.WriteField(f)
		}
		fr.WriteHeaders(HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: len(body) == 0, BlockFragment: block.Bytes()})
		for len(body) > 0 {
			n := min(frame, len(body))
			fr.WriteData(1, n == len(body), body[:n])
			body = body[n:]
		}
	}
}

// settingsRoundTrip sends a GET over a new connection of t to a server
// answering with respond, and returns the preface and the body read. The
// body is read once the client processed all the server wrote: reading it
// earlier gives the window back, and a frame above the window would fit.
func settingsRoundTrip(t *testing.T, tr *Transport, respond func(*Framer)) (prefaceSeen, []byte, error) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	done := make(chan struct{})
	seen := settingsServer(server, respond, done)
	cc, err := tr.newClientConn(client, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	resp, err := cc.RoundTrip(req)
	p := <-seen
	if err != nil {
		return p, nil, err
	}
	defer resp.Body.Close()
	<-done
	body, err := io.ReadAll(resp.Body)
	return p, body, err
}

var chromeSettings = []Setting{
	{ID: SettingHeaderTableSize, Val: 65536},
	{ID: SettingEnablePush, Val: 0},
	{ID: SettingInitialWindowSize, Val: 6291456},
	{ID: SettingMaxHeaderListSize, Val: 262144},
}

// Settings are sent exactly, in order, with the WINDOW_UPDATE given, or
// none for 0; without Settings the derived ones are sent.
func TestSettingsSent(t *testing.T) {
	for _, tt := range []struct {
		name     string
		settings []Setting
		update   uint32
		want     []Setting
		updates  []uint32
	}{
		{"chrome", chromeSettings, 15663105, chromeSettings, []uint32{15663105}},
		{"no window update", []Setting{{ID: SettingMaxConcurrentStreams, Val: 100}, {ID: 0x0a0a, Val: 7}}, 0,
			[]Setting{{ID: SettingMaxConcurrentStreams, Val: 100}, {ID: 0x0a0a, Val: 7}}, nil},
		{"empty", []Setting{}, 0, nil, nil},
		{"derived", nil, 0, []Setting{
			{ID: SettingEnablePush, Val: 0},
			{ID: SettingInitialWindowSize, Val: transportDefaultStreamFlow},
			{ID: SettingMaxFrameSize, Val: minMaxFrameSize},
			{ID: SettingMaxHeaderListSize, Val: 10 << 20},
		}, []uint32{transportDefaultConnFlow}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Transport{Settings: tt.settings, ConnWindowUpdate: tt.update}
			p, _, err := settingsRoundTrip(t, tr, respondWith(nil, nil, nil, nil, 0))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(p.settings, tt.want) {
				t.Errorf("settings %v, want %v", p.settings, tt.want)
			}
			if !slices.Equal(p.updates, tt.updates) {
				t.Errorf("window updates %v, want %v", p.updates, tt.updates)
			}
		})
	}
}

// The values announced are the ones enforced: the HPACK table, the stream
// and connection windows, the frame size and the header list limit, both
// when they allow what the server sends and when they refuse more.
func TestSettingsEnforced(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 100000)
	tableUpdate := func(size uint32) func(*Framer) {
		var block bytes.Buffer
		enc := hpack.NewEncoder(&block)
		enc.SetMaxDynamicTableSizeLimit(size)
		enc.SetMaxDynamicTableSize(size)
		return respondWith(enc, &block, nil, []byte("ok"), 16384)
	}
	for _, tt := range []struct {
		name     string
		settings []Setting
		update   uint32
		respond  func(*Framer)
		ok       bool
	}{
		{"table within HEADER_TABLE_SIZE", []Setting{{ID: SettingHeaderTableSize, Val: 65536}}, 0, tableUpdate(65536), true},
		{"table above HEADER_TABLE_SIZE", []Setting{{ID: SettingHeaderTableSize, Val: 65536}}, 0, tableUpdate(65537), false},
		{"table above the initial 4096", []Setting{}, 0, tableUpdate(4097), false},
		{"windows of 100000", []Setting{{ID: SettingInitialWindowSize, Val: 100000}}, 100000 - initialWindowSize,
			respondWith(nil, nil, nil, big, 16384), true},
		{"stream window of 99999", []Setting{{ID: SettingInitialWindowSize, Val: 99999}}, 100000 - initialWindowSize,
			respondWith(nil, nil, nil, big, 16384), false},
		{"connection window of 99999", []Setting{{ID: SettingInitialWindowSize, Val: 100000}}, 99999 - initialWindowSize,
			respondWith(nil, nil, nil, big, 16384), false},
		{"initial windows", []Setting{}, 0, respondWith(nil, nil, nil, big[:initialWindowSize], 16384), true},
		{"initial stream window", []Setting{}, 100000, respondWith(nil, nil, nil, big[:initialWindowSize+1], 16384), false},
		{"frame within MAX_FRAME_SIZE", []Setting{{ID: SettingMaxFrameSize, Val: 32768}, {ID: SettingInitialWindowSize, Val: 100000}}, 100000,
			respondWith(nil, nil, nil, big[:32768], 32768), true},
		{"frame above the initial 16384", []Setting{{ID: SettingInitialWindowSize, Val: 100000}}, 100000,
			respondWith(nil, nil, nil, big[:16385], 16385), false},
		{"headers within MAX_HEADER_LIST_SIZE", []Setting{{ID: SettingMaxHeaderListSize, Val: 1000}}, 0,
			respondWith(nil, nil, []hpack.HeaderField{{Name: "x-a", Value: strings.Repeat("a", 900)}}, nil, 0), true},
		{"headers above MAX_HEADER_LIST_SIZE", []Setting{{ID: SettingMaxHeaderListSize, Val: 1000}}, 0,
			respondWith(nil, nil, []hpack.HeaderField{{Name: "x-a", Value: strings.Repeat("a", 1000)}}, nil, 0), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The other fields allow more than the initial values: the
			// settings must replace them.
			tr := &Transport{Settings: tt.settings, ConnWindowUpdate: tt.update, MaxHeaderListSize: 1 << 20,
				MaxDecoderHeaderTableSize: 1 << 20, MaxReadFrameSize: 1 << 20}
			_, _, err := settingsRoundTrip(t, tr, tt.respond)
			if (err == nil) != tt.ok {
				t.Fatalf("error %v, want ok %v", err, tt.ok)
			}
		})
	}
}

func TestCheckSettings(t *testing.T) {
	for _, tt := range []struct {
		settings []Setting
		update   uint32
		ok       bool
	}{
		{chromeSettings, 15663105, true},
		{nil, 0, true},
		{[]Setting{{ID: 0x0a0a, Val: 1}, {ID: SettingNoRFC7540Priorities, Val: 1}}, 1<<31 - 1 - initialWindowSize, true},
		{[]Setting{{ID: SettingEnablePush, Val: 0}, {ID: SettingEnablePush, Val: 0}}, 0, false},
		{[]Setting{{ID: SettingEnablePush, Val: 1}}, 0, false},
		{[]Setting{{ID: SettingEnablePush, Val: 2}}, 0, false},
		{[]Setting{{ID: SettingInitialWindowSize, Val: 0}}, 0, false},
		{[]Setting{{ID: SettingInitialWindowSize, Val: 1 << 31}}, 0, false},
		{[]Setting{{ID: SettingMaxFrameSize, Val: 16383}}, 0, false},
		{[]Setting{{ID: SettingMaxHeaderListSize, Val: 0}}, 0, false},
		{[]Setting{{ID: SettingNoRFC7540Priorities, Val: 2}}, 0, false},
		{nil, 1<<31 - initialWindowSize, false},
	} {
		if err := CheckSettings(tt.settings, tt.update); (err == nil) != tt.ok {
			t.Errorf("CheckSettings(%v, %d) = %v, want ok %v", tt.settings, tt.update, err, tt.ok)
		}
	}
}
