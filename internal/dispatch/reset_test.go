package dispatch_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// resets returns the RST_STREAM frames the client sent on c.
func resets(t *testing.T, c *lab.Conn) int {
	t.Helper()
	frames, err := c.H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range frames {
		if f.Type == "RST_STREAM" {
			n++
		}
	}
	return n
}

func statusBlock(fields ...hpack.HeaderField) []byte {
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	for _, f := range fields {
		enc.WriteField(f)
	}
	return b.Bytes()
}

// A response read in full whose END_STREAM comes a moment later, in an
// empty DATA frame, ends without RST_STREAM, as in Chrome, even when the
// caller cancels its context on return. A body closed before its end still
// resets the stream.
func TestNoResetAfterFullBody(t *testing.T) {
	for _, tt := range []struct {
		name      string
		length    string // the declared Content-Length
		wantReset bool
	}{
		{"read in full", "2", false},
		{"closed early", "4", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{H2Conn: rawH2(func(fr *http2.Framer, stream uint32, _ int) bool {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, EndHeaders: true,
					BlockFragment: statusBlock(hpack.HeaderField{Name: "content-length", Value: tt.length})})
				fr.WriteData(stream, false, []byte("ok"))
				time.Sleep(100 * time.Millisecond)
				fr.WriteData(stream, true, nil)
				return true
			})})
			tr := transport(srv)
			defer tr.Close()
			for range 5 {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
				resp, err := tr.RoundTrip(req)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				io.ReadFull(resp.Body, make([]byte, 2))
				resp.Body.Close()
				cancel()
			}
			time.Sleep(700 * time.Millisecond) // the last END_STREAM and any reset
			tr.Close()
			n := resets(t, srv.NextConn(t))
			if tt.wantReset && n != 5 || !tt.wantReset && n != 0 {
				t.Fatalf("%d RST_STREAM frames for 5 requests", n)
			}
		})
	}
}

// postServer answers each request with a bare HEADERS frame carrying
// END_STREAM, once the request body ended.
func postServer(c net.Conn) {
	defer c.Close()
	if _, err := io.ReadFull(c, make([]byte, len(http2.ClientPreface))); err != nil {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.WriteSettings()
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		var end bool
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				fr.WriteSettingsAck()
			}
		case *http2.HeadersFrame:
			end = f.StreamEnded()
		case *http2.DataFrame:
			end = f.StreamEnded()
			if n := f.Length; n > 0 {
				fr.WriteWindowUpdate(0, n)
			}
		}
		if end {
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.Header().StreamID, EndHeaders: true, EndStream: true,
				BlockFragment: statusBlock()})
		}
	}
}

// A POST answered by HEADERS with END_STREAM is finished on both sides; a
// caller that cancels its context on return must not reset it.
func TestNoResetAfterHeadersEndStream(t *testing.T) {
	if testing.Short() {
		t.Skip("20,000 requests")
	}
	srv := lab.Start(t, lab.Options{H2Conn: postServer})
	tr := transport(srv)
	defer tr.Close()
	const total, parallel = 20000, 8
	var wg sync.WaitGroup
	next := make(chan struct{}, total)
	for range total {
		next <- struct{}{}
	}
	close(next)
	for range parallel {
		wg.Go(func() {
			for range next {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com/", strings.NewReader("body"))
				resp, err := tr.RoundTrip(req)
				cancel()
				if err != nil {
					t.Error(err)
					return
				}
				resp.Body.Close()
			}
		})
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	tr.Close()
	if n := resets(t, srv.NextConn(t)); n != 0 {
		t.Fatalf("%d RST_STREAM frames for %d finished requests", n, total)
	}
}
