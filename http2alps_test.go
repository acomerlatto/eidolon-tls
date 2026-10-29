package eidolon_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// alpsFrame is an HTTP/2 frame on stream 0 in the ALPS data of a server.
func alpsFrame(typ xhttp2.FrameType, payload ...byte) []byte {
	var b bytes.Buffer
	xhttp2.NewFramer(&b, nil).WriteRawFrame(typ, 0, 0, payload)
	return b.Bytes()
}

// A server whose ALPS sets HEADER_TABLE_SIZE to 0: with HTTP2ALPSChromium,
// the default, the first HEADERS starts with the table size update to 0
// that the setting asks for; with HTTP2ALPSIgnore, it does not. A server
// whose ALPS has a PING: the request fails, and the connection closes
// after the preface with the GOAWAY of Chromium, unless the ALPS is
// ignored. As in Chromium, the request is not sent again.
func TestHTTP2ALPS(t *testing.T) {
	ignore := eidolon.Chrome156Linux().HTTP2
	ignore.ALPS = eidolon.HTTP2ALPSIgnore
	tableSize0 := alpsFrame(xhttp2.FrameSettings, 0, 1, 0, 0, 0, 0)
	ping := alpsFrame(xhttp2.FramePing, make([]byte, 8)...)
	for _, tt := range []struct {
		name  string
		alps  []byte
		opts  []eidolon.Option
		want  string // the error of the request, or "" for none
		first byte   // the first byte of the first HEADERS block
	}{
		{"settings", tableSize0, nil, "", 0x20},
		{"settings, profile", tableSize0, []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.Chrome156Linux().HTTP2)}, "", 0x20},
		{"settings ignored", tableSize0, []eidolon.Option{eidolon.WithHTTP2Settings(ignore)}, "", 0x82},
		{"no ALPS", nil, nil, "", 0x82},
		{"PING", ping, nil, "Error parsing ALPS: 2", 0},
		{"PING ignored", ping, []eidolon.Option{eidolon.WithHTTP2Settings(ignore)}, "", 0x82},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := lab.Options{NextProtos: []string{"h2"}}
			if tt.alps != nil {
				opts.ALPS = map[string][]byte{"h2": tt.alps}
			}
			if tt.want != "" {
				// Read all the client sends: the HTTP/2 server of Go may
				// close before it reads the GOAWAY, once its own SETTINGS
				// cannot be written.
				opts.H2Conn = func(c net.Conn) { io.Copy(io.Discard, c) }
			}
			srv := lab.Start(t, opts)
			c := newClient(t, srv, tt.opts...)
			resp, err := c.Get("https://example.com/")
			if err == nil {
				resp.Body.Close()
			}
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("request: %v, want %q", err, tt.want)
			}
			conn := srv.NextConn(t)
			if tt.alps != nil && conn.ALPS == nil {
				t.Error("no ALPS negotiated")
			}
			if tt.want != "" {
				<-conn.Done()
			}
			frames, err := conn.H2Frames()
			if err != nil {
				t.Fatal(err)
			}
			var types []string
			for _, f := range frames {
				types = append(types, f.Type)
				if f.Type == "HEADERS" && f.Block[0] != tt.first {
					t.Errorf("HEADERS block starts with %#x, want %#x", f.Block[0], tt.first)
				}
				if f.Type == "GOAWAY" && (f.ErrCode != uint32(xhttp2.ErrCodeProtocol) || f.Debug != tt.want) {
					t.Errorf("GOAWAY %d %q", f.ErrCode, f.Debug)
				}
			}
			if tt.want != "" && strings.Join(types, " ") != "SETTINGS WINDOW_UPDATE GOAWAY" {
				t.Errorf("client sent %v", types)
			}
			if n := srv.Accepted(); n != 1 {
				t.Errorf("%d connections, want 1", n)
			}
		})
	}
}

// A connection the HTTP/1.1 pool dials for an origin that answered over
// HTTP/1.1, and that negotiates h2 with malformed ALPS, fails the request
// as well: the first connection closes after its response, and the second
// goes to a server with h2 and a PING in its ALPS.
func TestHTTP2ALPSFromHTTP1(t *testing.T) {
	cert, err := lab.NewCertificate(time.Hour, lab.ServerName)
	if err != nil {
		t.Fatal(err)
	}
	h1 := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Certificate: &cert,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Connection", "close")
			io.WriteString(w, "ok")
		})})
	h2 := lab.Start(t, lab.Options{NextProtos: []string{"h2"}, Certificate: &cert,
		ALPS:   map[string][]byte{"h2": alpsFrame(xhttp2.FramePing, make([]byte, 8)...)},
		H2Conn: func(c net.Conn) { io.Copy(io.Discard, c) }})
	var dials atomic.Int32
	c, err := eidolon.New(
		eidolon.WithClientHello(chromeSpec),
		eidolon.WithRootCAs(h1.RootCAs),
		eidolon.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			addr := h2.Addr
			if dials.Add(1) == 1 {
				addr = h1.Addr
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if _, err := c.Get("https://example.com/"); err == nil || !strings.Contains(err.Error(), "Error parsing ALPS: 2") {
		t.Fatalf("second request: %v", err)
	}
	if n := dials.Load(); n != 2 {
		t.Errorf("%d dials, want 2", n)
	}
}
