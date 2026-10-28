package dispatch_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// orderedPost returns a POST with a body that GetBody can rewind and an
// order for x-b before x-a.
func orderedPost(t *testing.T, url string) *http.Request {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("payload"))
	req.Header.Set("X-A", "1")
	req.Header.Set("X-B", "2")
	req.Header["Header-Order:"] = []string{"x-b", "x-a"}
	return req
}

// headerNames returns the regular header names of each HEADERS frame of
// the connections, in order.
func headerNames(t *testing.T, conns ...*lab.Conn) [][]string {
	t.Helper()
	var all [][]string
	for _, c := range conns {
		frames, err := c.H2Frames()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range frames {
			if f.Type != "HEADERS" {
				continue
			}
			var names []string
			for _, h := range f.Headers {
				if !strings.HasPrefix(h.Name, ":") {
					names = append(names, h.Name)
				}
			}
			all = append(all, names)
		}
	}
	return all
}

// A refused stream was not processed (RFC 9113 section 8.7): it is sent
// again at once, whatever the method, at most twice, as Chrome does, with
// the same header order. The engine of x/net retried six times more with
// a backoff of up to 32 s.
func TestRefusedStreamRetried(t *testing.T) {
	for _, tt := range []struct {
		name    string
		refuse  int // requests refused before a 200
		wantErr bool
	}{
		{"once", 1, false},
		{"twice", 2, false},
		{"always", 100, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			srv := lab.Start(t, lab.Options{H2Conn: rawH2(func(fr *http2.Framer, stream uint32, _ int) bool {
				if int(attempts.Add(1)) <= tt.refuse {
					fr.WriteRSTStream(stream, http2.ErrCodeRefusedStream)
				} else {
					writeOK(fr, stream)
				}
				return true
			})})
			tr := transport(srv)
			defer tr.Close()
			start := time.Now()
			resp, err := tr.RoundTrip(orderedPost(t, "https://example.com/"))
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("took %v: retries wait", d)
			}
			var se http2.StreamError
			switch {
			case tt.wantErr && (!errors.As(err, &se) || se.Code != http2.ErrCodeRefusedStream):
				t.Fatalf("err = %v, want REFUSED_STREAM", err)
			case !tt.wantErr && err != nil:
				t.Fatal(err)
			case !tt.wantErr:
				resp.Body.Close()
			}
			want := min(tt.refuse+1, 3)
			if n := int(attempts.Load()); n != want {
				t.Fatalf("%d attempts, want %d", n, want)
			}
			tr.Close()
			if n := srv.Accepted(); n != 1 {
				t.Fatalf("%d connections, want 1", n)
			}
			names := headerNames(t, srv.NextConn(t))
			for n, got := range names {
				if i := slices.Index(got, "x-b"); i < 0 || i+1 >= len(got) || got[i+1] != "x-a" {
					t.Fatalf("attempt %d: headers %v, want x-b then x-a", n+1, got)
				}
			}
		})
	}
}

// A graceful GOAWAY leaves the streams above its last one unprocessed:
// they go again on a new connection, whatever the method, within the
// same budget of two retries.
func TestGracefulGoAwayRetried(t *testing.T) {
	for _, tt := range []struct {
		name    string
		always  bool // every connection sends GOAWAY on its first request
		wantErr bool
	}{
		{"once", false, false},
		{"always", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var conns atomic.Int32
			srv := lab.Start(t, lab.Options{H2Conn: func(c net.Conn) {
				first := conns.Add(1) == 1
				rawH2(func(fr *http2.Framer, stream uint32, _ int) bool {
					if first || tt.always {
						fr.WriteGoAway(0, http2.ErrCodeNo, nil)
						return false
					}
					writeOK(fr, stream)
					return true
				})(c)
			}})
			tr := transport(srv)
			defer tr.Close()
			resp, body, err := do(t, tr, http.MethodPost, "https://example.com/", "payload")
			if tt.wantErr {
				if err == nil {
					t.Fatal("no error")
				}
			} else if err != nil || resp.ProtoMajor != 2 || body != "h2" {
				t.Fatalf("%q, %v", body, err)
			}
			want := map[bool]int{false: 2, true: 3}[tt.always]
			if n := srv.Accepted(); n != want {
				t.Fatalf("%d connections, want %d", n, want)
			}
		})
	}
}

// A GOAWAY with an error code fails the unprocessed streams with the code,
// on any stream, as Chrome (ERR_HTTP2_PROTOCOL_ERROR): nothing is sent
// again, not even a GET.
func TestGoAwayErrorNotRetried(t *testing.T) {
	srv := lab.Start(t, lab.Options{H2Conn: rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
		if n == 1 {
			writeOK(fr, stream)
			return true
		}
		fr.WriteGoAway(stream-2, http2.ErrCodeEnhanceYourCalm, nil)
		return false
	})})
	tr := transport(srv)
	defer tr.Close()
	if _, body, err := do(t, tr, http.MethodGet, "https://example.com/", ""); err != nil || body != "h2" {
		t.Fatalf("first request: %q, %v", body, err)
	}
	_, _, err := do(t, tr, http.MethodGet, "https://example.com/", "")
	var ge http2.GoAwayError
	if !errors.As(err, &ge) || ge.ErrCode != http2.ErrCodeEnhanceYourCalm {
		t.Fatalf("err = %v, want GoAwayError with ENHANCE_YOUR_CALM", err)
	}
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
}

// An idle HTTP/2 connection lost when reused: the GET goes again on a new
// connection, which negotiates http/1.1 and goes to the HTTP/1.1 engine
// before any byte, with the same header order; nothing already sent on
// HTTP/2 is sent there again. A POST is not sent again (R3, R6).
func TestReplayAcrossALPNChange(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			h2srv := lab.Start(t, lab.Options{H2Conn: func(c net.Conn) {
				rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
					if n == 1 {
						writeOK(fr, stream)
						return true
					}
					c.Close() // lost with the request sent
					return false
				})(c)
			}})
			var h1reqs atomic.Int32
			h1srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h1reqs.Add(1)
				io.WriteString(w, "h1")
			})})
			tr := transport(h2srv)
			tr.TLS.RootCAs.AddCert(h1srv.Certificate)
			var dials atomic.Int32
			tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				addr := h2srv.Addr
				if dials.Add(1) > 1 {
					addr = h1srv.Addr
				}
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}
			defer tr.Close()
			if _, body, err := do(t, tr, http.MethodGet, "https://example.com/", ""); err != nil || body != "h2" {
				t.Fatalf("first request: %q, %v", body, err)
			}

			req := orderedPost(t, "https://example.com/")
			req.Method = method
			if method == http.MethodGet {
				req.Body, req.GetBody, req.ContentLength = nil, nil, 0
			}
			resp, err := tr.RoundTrip(req)
			if method == http.MethodPost {
				if err == nil {
					resp.Body.Close()
					t.Fatal("POST sent again after a lost connection")
				}
				if n := h1srv.Accepted(); n != 0 {
					t.Fatalf("%d HTTP/1.1 connections, want 0", n)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.ProtoMajor != 1 || string(body) != "h1" {
				t.Fatalf("%s %q", resp.Proto, body)
			}
			if n := h1reqs.Load(); n != 1 {
				t.Fatalf("%d HTTP/1.1 requests, want 1", n)
			}
			tr.Close()
			if names := headerNames(t, h2srv.NextConn(t)); len(names) != 2 {
				t.Fatalf("%d HTTP/2 requests, want 2", len(names))
			}
			raw := string(h1srv.NextConn(t).Bytes())
			if a, b := strings.Index(raw, "X-A:"), strings.Index(raw, "X-B:"); a < 0 || b < 0 || b > a {
				t.Fatalf("HTTP/1.1 request without x-b before x-a:\n%s", raw)
			}
		})
	}
}
