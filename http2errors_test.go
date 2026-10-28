package eidolon_test

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// A server that answers the HEADERS of a request with a PING on stream 1:
// with HTTP2ErrorsChromium, the default, the client closes the
// connection with GOAWAY PROTOCOL_ERROR and the debug data of Chromium;
// with HTTP2ErrorsGo, it closes the connection without GOAWAY, which the
// read loop of Go writes and does not flush. No RST_STREAM follows the
// GOAWAY of Chromium: the request learns the error with the connection,
// and each case runs 10 times, as the streams end while it closes.
func TestHTTP2Errors(t *testing.T) {
	goSettings := eidolon.Chrome156Linux().HTTP2
	goSettings.Errors = eidolon.HTTP2ErrorsGo
	for _, tt := range []struct {
		name string
		opts []eidolon.Option
		want string
	}{
		{"default", nil, `GOAWAY 1 "Framer error: 1 (INVALID_STREAM_ID)."`},
		{"profile", []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.Chrome156Linux().HTTP2)}, `GOAWAY 1 "Framer error: 1 (INVALID_STREAM_ID)."`},
		{"Go", []eidolon.Option{eidolon.WithHTTP2Settings(goSettings)}, "no GOAWAY"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for range 10 {
				testHTTP2Error(t, tt.opts, tt.want)
			}
		})
	}
}

// testHTTP2Error runs a case of TestHTTP2Errors.
func testHTTP2Error(t *testing.T, opts []eidolon.Option, want string) {
	t.Helper()
	closed := make(chan struct{})
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}, H2Conn: func(c net.Conn) {
		defer close(closed)
		defer c.Close()
		if _, err := io.ReadFull(c, make([]byte, len(xhttp2.ClientPreface))); err != nil {
			return
		}
		fr := xhttp2.NewFramer(c, c)
		fr.WriteSettings()
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if _, ok := f.(*xhttp2.HeadersFrame); ok {
				fr.WriteRawFrame(xhttp2.FramePing, 0, 1, make([]byte, 8))
			}
		}
	}})
	c := newClient(t, srv, opts...)
	if _, err := c.Get("https://example.com/"); err == nil {
		t.Fatal("request answered")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("connection open")
	}
	frames, err := srv.NextConn(t).H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	got := "no GOAWAY"
	if f := frames[len(frames)-1]; f.Type == "GOAWAY" {
		got = fmt.Sprintf("GOAWAY %d %q", f.ErrCode, f.Debug)
	}
	if got != want {
		t.Errorf("%s, want %s", got, want)
	}
}
