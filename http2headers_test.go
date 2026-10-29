package eidolon_test

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	xhttp2 "golang.org/x/net/http2"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// A header block larger than a frame: with HTTP2HeaderFramingChromium,
// the default, the HEADERS and CONTINUATION frames carry at most 16374
// bytes, as Chromium; with HTTP2HeaderFramingGo, the HEADERS is larger.
func TestHTTP2HeaderFraming(t *testing.T) {
	goFraming := eidolon.Chrome156Linux().HTTP2
	goFraming.HeaderFraming = eidolon.HTTP2HeaderFramingGo
	for _, tt := range []struct {
		name     string
		opts     []eidolon.Option
		chromium bool
	}{
		{"default", nil, true},
		{"profile", []eidolon.Option{eidolon.WithHTTP2Settings(eidolon.Chrome156Linux().HTTP2)}, true},
		{"Go", []eidolon.Option{eidolon.WithHTTP2Settings(goFraming)}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
			c := newClient(t, srv, tt.opts...)
			req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
			req.Header.Set("X-Large", strings.Repeat("abcdefghij", 4000))
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			// Read without HPACK: H2Frames joins CONTINUATION to HEADERS.
			data := bytes.TrimPrefix(srv.NextConn(t).Bytes(), []byte(xhttp2.ClientPreface))
			fr := xhttp2.NewFramer(io.Discard, bytes.NewReader(data))
			fr.SetMaxReadFrameSize(1 << 24)
			var sizes []uint32
			for {
				f, err := fr.ReadFrame()
				if err != nil {
					break
				}
				if h := f.Header(); h.Type == xhttp2.FrameHeaders || h.Type == xhttp2.FrameContinuation {
					sizes = append(sizes, h.Length)
				}
			}
			if len(sizes) < 2 && tt.chromium || len(sizes) == 0 {
				t.Fatalf("header frames of %v bytes", sizes)
			}
			if over := sizes[0] > 16374; over == tt.chromium {
				t.Errorf("header frames of %v bytes", sizes)
			}
			for _, n := range sizes[1:] {
				if n > 16374 && tt.chromium {
					t.Errorf("header frames of %v bytes", sizes)
				}
			}
		})
	}
}
