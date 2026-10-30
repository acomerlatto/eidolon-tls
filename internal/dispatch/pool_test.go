package dispatch_test

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// fetch sends a GET and reads the whole body.
func fetch(t *testing.T, rt http.RoundTripper, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Error(err)
		return nil
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Error(err)
		return nil
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Error(err)
	}
	return resp
}

func headersFrames(t *testing.T, c *lab.Conn) int {
	t.Helper()
	frames, err := c.H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range frames {
		if f.Type == "HEADERS" {
			n++
		}
	}
	return n
}

// Sequential requests to one origin share the HTTP/2 connection, and every
// response carries the TLS state.
func TestPoolH2Reuse(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	tr := transport(srv)
	defer tr.Close()
	for _, path := range []string{"/1", "/2", "/3"} {
		if resp := fetch(t, tr, "https://example.com"+path); resp != nil && resp.TLS == nil {
			t.Fatalf("%s: Response.TLS is nil", path)
		}
	}
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
	if n := headersFrames(t, srv.NextConn(t)); n != 3 {
		t.Fatalf("%d HEADERS frames on the connection, want 3", n)
	}
}

// Concurrent requests multiplex on the pooled connection: the handler only
// answers once all of them are in flight.
func TestPoolH2Multiplex(t *testing.T) {
	const n = 4
	var arrived sync.WaitGroup
	arrived.Add(n)
	srv := lab.Start(t, lab.Options{
		NextProtos: []string{"h2"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/c" {
				arrived.Done()
				arrived.Wait()
			}
			io.WriteString(w, "ok")
		}),
	})
	tr := transport(srv)
	defer tr.Close()
	fetch(t, tr, "https://example.com/warm")

	var wg sync.WaitGroup
	for range n {
		wg.Go(func() { fetch(t, tr, "https://example.com/c") })
	}
	wg.Wait()
	if c := srv.Accepted(); c != 1 {
		t.Fatalf("%d connections, want 1", c)
	}
}

// The pool key is the normalized origin: spellings of the same origin share
// a connection, different origins never do (no coalescing). A trailing dot
// makes another origin, as in Chrome.
func TestPoolH2Key(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	tr := transport(srv)
	defer tr.Close()
	for _, url := range []string{
		"https://example.com/",
		"https://EXAMPLE.com/",
		"https://example.com:443/",
		"https://example.com./",
		"https://example.com:8443/",
		"https://Example.COM:8443/",
	} {
		fetch(t, tr, url)
	}
	if n := srv.Accepted(); n != 3 {
		t.Fatalf("%d connections, want 3 (one per origin)", n)
	}
}

// CloseIdleConnections closes the idle HTTP/2 connection: the next request
// dials again.
func TestPoolH2CloseIdleConnections(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	tr := transport(srv)
	defer tr.Close()
	fetch(t, tr, "https://example.com/1")
	tr.CloseIdleConnections()
	fetch(t, tr, "https://example.com/2")
	if n := srv.Accepted(); n != 2 {
		t.Fatalf("%d connections, want 2", n)
	}
}

// A pooled connection closed by the server between requests is not reused:
// the next request dials again and succeeds.
func TestPoolH2ServerClosedConnection(t *testing.T) {
	first := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	second := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	roots := x509.NewCertPool()
	roots.AddCert(first.Certificate)
	roots.AddCert(second.Certificate)
	var dials atomic.Int32
	tr := &dispatch.Transport{
		Spec: chromeSpec,
		TLS:  &utls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			addr := first.Addr
			if dials.Add(1) > 1 {
				addr = second.Addr
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	defer tr.Close()
	fetch(t, tr, "https://example.com/1")
	first.Close()
	if resp := fetch(t, tr, "https://example.com/2"); resp == nil {
		t.FailNow()
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials, want 2", n)
	}
}

// dropConn closes itself right after the next write once armed: the
// request reaches the wire and the connection is lost before the response.
// Reads fail from that write on, so a response that comes back before the
// Close is never seen. A write of a frame without payload, such as the
// SETTINGS ACK the read loop of a new connection may send after GotConn,
// is not the request and does not count.
type dropConn struct {
	net.Conn
	armed   *atomic.Bool
	dropped atomic.Bool
}

// frameOnlyRecord is a TLS 1.3 record carrying a 9-byte frame header and
// nothing else: 5 bytes of header, 1 of content type and a 16-byte tag.
const frameOnlyRecord = 5 + 9 + 1 + 16

func (c *dropConn) Write(p []byte) (int, error) {
	drop := len(p) > frameOnlyRecord && c.armed.CompareAndSwap(true, false)
	if drop {
		c.dropped.Store(true)
	}
	n, err := c.Conn.Write(p)
	if drop {
		c.Conn.Close()
	}
	return n, err
}

func (c *dropConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.dropped.Load() {
		return 0, net.ErrClosed
	}
	return n, err
}

// Section 6.3: losing a reused idle connection replays the request on a new
// connection only when it can be replayed (safe method or idempotency key,
// and a body that GetBody can recreate). In exact mode the idempotency key
// counts only among the fields sent.
func TestPoolH2ReplayAfterLostIdleConnection(t *testing.T) {
	exact := []order.Field{{Name: "Host", Value: "example.com"}}
	tests := []struct {
		name   string
		method string
		body   bool
		getter bool
		key    bool          // Idempotency-Key in req.Header
		exact  []order.Field // exact mode
		fresh  bool          // the lost connection is new, not reused
		idem   bool          // Transport.Idempotent
		replay bool
	}{
		{name: "GET", method: http.MethodGet, replay: true},
		{name: "GET on a new connection", method: http.MethodGet, fresh: true},
		{name: "POST without GetBody", method: http.MethodPost, body: true, key: true},
		{name: "POST without idempotency key", method: http.MethodPost, body: true, getter: true},
		{name: "POST with key and GetBody", method: http.MethodPost, body: true, getter: true, key: true, replay: true},
		{name: "POST of an idempotent transport", method: http.MethodPost, body: true, getter: true, idem: true, replay: true},
		{name: "POST of an idempotent transport without GetBody", method: http.MethodPost, body: true, idem: true},
		{name: "exact POST with key in Header", method: http.MethodPost, body: true, getter: true, key: true, exact: exact},
		{name: "exact POST with key sent", method: http.MethodPost, body: true, getter: true,
			exact: append(slices.Clone(exact), order.Field{Name: "idempotency-key", Value: "k1"}), replay: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{
				NextProtos: []string{"h2"},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := io.ReadAll(r.Body)
					w.Write(append([]byte("got:"), b...))
				}),
			})
			var armed atomic.Bool
			var dials atomic.Int32
			tr := &dispatch.Transport{
				Spec: chromeSpec,
				TLS:  &utls.Config{RootCAs: srv.RootCAs},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					dials.Add(1)
					var d net.Dialer
					c, err := d.DialContext(ctx, network, srv.Addr)
					if err != nil {
						return nil, err
					}
					return &dropConn{Conn: c, armed: &armed}, nil
				},
				Idempotent: tt.idem,
			}
			defer tr.Close()
			if !tt.fresh {
				fetch(t, tr, "https://example.com/warm")
			}

			var body io.Reader
			if tt.body {
				body = io.NopCloser(strings.NewReader("payload")) // no GetBody
			}
			ctx := context.Background()
			if tt.exact != nil {
				ctx = order.WithExact(ctx, tt.exact)
			}
			req, _ := http.NewRequestWithContext(ctx, tt.method, "https://example.com/", body)
			if tt.getter {
				req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("payload")), nil }
			}
			if tt.key {
				req.Header.Set("Idempotency-Key", "k1")
			}
			if tt.fresh {
				// The engine reports the connection right before writing
				// the request; the caller's trace runs with the
				// dispatcher's.
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
					GotConn: func(httptrace.GotConnInfo) { armed.Store(true) },
				}))
			} else {
				armed.Store(true)
			}
			resp, err := tr.RoundTrip(req)
			if !tt.replay {
				if err == nil {
					resp.Body.Close()
					t.Fatal("request replayed after the connection was lost")
				}
				t.Logf("error: %v", err)
				if n := dials.Load(); n != 1 {
					t.Fatalf("%d dials, want 1", n)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			want := "got:"
			if tt.body {
				want += "payload"
			}
			if string(got) != want {
				t.Fatalf("body %q, want %q", got, want)
			}
			if n := dials.Load(); n != 2 {
				t.Fatalf("%d dials, want 2", n)
			}
		})
	}
}

// A request that fails on a live reused connection, here a stream reset by
// the server, is not replayed: only a lost connection allows it.
func TestPoolH2NoReplayOnStreamError(t *testing.T) {
	var aborted atomic.Int32
	srv := lab.Start(t, lab.Options{
		NextProtos: []string{"h2"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/abort" {
				aborted.Add(1)
				panic(http.ErrAbortHandler)
			}
			io.WriteString(w, "ok")
		}),
	})
	tr := transport(srv)
	defer tr.Close()
	fetch(t, tr, "https://example.com/warm")
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/abort", nil)
	if resp, err := tr.RoundTrip(req); err == nil {
		resp.Body.Close()
		t.Fatal("aborted stream returned a response")
	}
	if n := aborted.Load(); n != 1 {
		t.Fatalf("server saw %d attempts, want 1", n)
	}
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
}
