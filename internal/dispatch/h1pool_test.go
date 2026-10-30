package dispatch_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// h1Lab starts an HTTP/1.1 lab over TLS, or over plain TCP when plain.
func h1Lab(t *testing.T, plain bool, h http.Handler) (*lab.Server, string) {
	t.Helper()
	if plain {
		return lab.Start(t, lab.Options{Plain: true, Handler: h}), "http://example.com"
	}
	return lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: h}), "https://example.com"
}

// send sends a request with ctx and reads the whole body.
func send(ctx context.Context, rt http.RoundTripper, method, url string, body io.Reader) (string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return "", err
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// hijack answers with raw bytes. With close the server then closes the
// connection; otherwise it reads until the client closes it.
func hijack(w http.ResponseWriter, raw string, close bool) {
	c, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		panic(err)
	}
	buf.WriteString(raw)
	buf.Flush()
	if !close {
		io.Copy(io.Discard, c)
	}
	c.Close()
}

// Sequential requests share one connection over http:// and https://,
// including responses without a body.
func TestH1PoolReuse(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(map[bool]string{false: "TLS", true: "plain"}[plain], func(t *testing.T) {
			srv, base := h1Lab(t, plain, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/empty" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				io.WriteString(w, "ok")
			}))
			tr := transport(srv)
			defer tr.Close()
			ctx := context.Background()
			for _, step := range []struct{ method, path string }{
				{http.MethodGet, "/a"}, {http.MethodHead, "/b"}, {http.MethodGet, "/empty"},
				{http.MethodPost, "/c"}, {http.MethodGet, "/d"},
			} {
				if _, err := send(ctx, tr, step.method, base+step.path, nil); err != nil {
					t.Fatalf("%s %s: %v", step.method, step.path, err)
				}
			}
			// A request refused before writing anything leaves the
			// connection as it was.
			req, _ := http.NewRequest(http.MethodGet, base+"/bad", nil)
			req.Header.Set("X-Bad", " edge space")
			if _, err := tr.RoundTrip(req); err == nil {
				t.Fatal("invalid request sent")
			}
			if _, err := send(ctx, tr, http.MethodGet, base+"/e", nil); err != nil {
				t.Fatal(err)
			}
			if n := srv.Accepted(); n != 1 {
				t.Fatalf("%d connections, want 1", n)
			}
		})
	}
}

// At most six connections per origin, as in Chrome; the other requests
// wait for one to be free.
func TestH1PoolLimit(t *testing.T) {
	var inFlight, peak atomic.Int32
	srv, base := h1Lab(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		inFlight.Add(-1)
		io.WriteString(w, "ok")
	}))
	tr := transport(srv)
	defer tr.Close()
	fetch(t, tr, base+"/warm") // the origin is learned as http/1.1
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { fetch(t, tr, base+"/") })
	}
	wg.Wait()
	if n := srv.Accepted(); n != dispatch.DefaultMaxConnsPerHost {
		t.Fatalf("%d connections, want %d", n, dispatch.DefaultMaxConnsPerHost)
	}
	if p := peak.Load(); p != dispatch.DefaultMaxConnsPerHost {
		t.Fatalf("%d requests at once, want %d", p, dispatch.DefaultMaxConnsPerHost)
	}
}

// A request waiting for a free connection stops at its own context and
// leaves no trace: the connection then serves the next request.
func TestH1PoolWaiterOwnContext(t *testing.T) {
	release := make(chan struct{})
	srv, base := h1Lab(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			<-release
		}
		io.WriteString(w, "ok")
	}))
	tr := transport(srv)
	tr.MaxConnsPerHost = 1
	defer tr.Close()
	fetch(t, tr, base+"/warm")

	held := make(chan error, 1)
	go func() {
		_, err := send(context.Background(), tr, http.MethodGet, base+"/hold", nil)
		held <- err
	}()
	time.Sleep(50 * time.Millisecond) // /hold takes the connection

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := send(ctx, tr, http.MethodGet, base+"/", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter: %v, want its deadline", err)
	}
	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if _, err := send(context.Background(), tr, http.MethodGet, base+"/", nil); err != nil {
		t.Fatal(err)
	}
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
}

// A connection is handed to a waiting request only if the server neither
// sent bytes after the response nor closed it, as for an idle one: the
// waiter gets a new connection, and neither reads the extra bytes as its
// response nor sends a body it cannot replay on a dead connection.
func TestH1PoolWaiterGetsCheckedConnection(t *testing.T) {
	for _, tt := range []struct {
		name  string
		raw   string
		close bool
	}{
		{"bytes after the response", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbad", false},
		{"closed by the server", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			answered := make(chan struct{})
			srv, base := h1Lab(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/first" {
					c, buf, _ := http.NewResponseController(w).Hijack()
					buf.WriteString(tt.raw)
					buf.Flush()
					if tt.close {
						c.Close()
					}
					close(answered)
					if !tt.close {
						io.Copy(io.Discard, c)
						c.Close()
					}
					return
				}
				body, _ := io.ReadAll(r.Body)
				io.WriteString(w, "second "+string(body))
			}))
			tr := transport(srv)
			tr.MaxConnsPerHost = 1
			defer tr.Close()

			req, _ := http.NewRequest(http.MethodGet, base+"/first", nil)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			<-answered
			got := make(chan string, 1)
			go func() {
				// A body without GetBody cannot be replayed.
				body, err := send(context.Background(), tr, http.MethodPost, base+"/second", io.NopCloser(strings.NewReader("data")))
				if err != nil {
					body = err.Error()
				}
				got <- body
			}()
			time.Sleep(50 * time.Millisecond) // the second request waits
			if b, _ := io.ReadAll(resp.Body); string(b) != "ok" {
				t.Fatalf("first body %q", b)
			}
			resp.Body.Close()
			if b := <-got; b != "second data" {
				t.Fatalf("second: %q, want %q", b, "second data")
			}
			if n := srv.Accepted(); n != 2 {
				t.Fatalf("%d connections, want 2", n)
			}
		})
	}
}

// Close wakes the requests waiting for a connection.
func TestH1PoolCloseWakesWaiters(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	srv, base := h1Lab(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			<-release
		}
		io.WriteString(w, "ok")
	}))
	tr := transport(srv)
	tr.MaxConnsPerHost = 1
	fetch(t, tr, base+"/warm")
	go send(context.Background(), tr, http.MethodGet, base+"/hold", nil)
	time.Sleep(50 * time.Millisecond)

	errc := make(chan error, 1)
	go func() {
		_, err := send(context.Background(), tr, http.MethodGet, base+"/", nil)
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	tr.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, dispatch.ErrClosed) {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter still blocked after Close")
	}
}

// The connection is not reused when the body is closed before EOF, when
// either side asks to close it, or when the response has both
// Transfer-Encoding and Content-Length (section 6.3).
func TestH1PoolNotReused(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		header  http.Header
		partial bool          // close the body before EOF
		close   bool          // Request.Close
		exact   []order.Field // exact mode
		body    string
	}{
		{
			name:    "body closed early",
			handler: func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("x", 1<<16)) },
			partial: true,
		},
		{
			name: "response Connection: close",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Connection", "close")
				io.WriteString(w, "ok")
			},
			body: "ok",
		},
		{
			// The server ignores the request and answers with keep-alive.
			name: "request Connection: close",
			handler: func(w http.ResponseWriter, r *http.Request) {
				hijack(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", false)
			},
			header: http.Header{"Connection": {"close"}},
			body:   "ok",
		},
		{
			// The same in exact mode, from the fields sent.
			name: "exact Connection: close",
			handler: func(w http.ResponseWriter, r *http.Request) {
				hijack(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", false)
			},
			exact: []order.Field{{Name: "Host", Value: "example.com"}, {Name: "connection", Value: "Close"}},
			body:  "ok",
		},
		{
			// Request.Close sends no Connection field, as Chrome.
			name: "Request.Close",
			handler: func(w http.ResponseWriter, r *http.Request) {
				body := "ok"
				if r.Header["Connection"] != nil || r.Close {
					body = "no"
				}
				hijack(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"+body, false)
			},
			close: true,
			body:  "ok",
		},
		{
			name: "bytes after the response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				hijack(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA", false)
			},
			body: "ok",
		},
		{
			name: "HTTP/1.0 without keep-alive",
			handler: func(w http.ResponseWriter, r *http.Request) {
				hijack(w, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", false)
			},
			body: "ok",
		},
		{
			name: "Transfer-Encoding and Content-Length",
			handler: func(w http.ResponseWriter, r *http.Request) {
				hijack(w, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n", false)
			},
			body: "ok",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, base := h1Lab(t, false, tt.handler)
			tr := transport(srv)
			defer tr.Close()
			ctx := context.Background()
			if tt.exact != nil {
				ctx = order.WithExact(ctx, tt.exact)
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
			for k, v := range tt.header {
				req.Header[k] = v
			}
			req.Close = tt.close
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			if tt.partial {
				resp.Body.Read(make([]byte, 10))
			} else if got, err := io.ReadAll(resp.Body); err != nil || string(got) != tt.body {
				t.Fatalf("body %q, %v; want %q", got, err, tt.body)
			}
			resp.Body.Close()
			select {
			case <-srv.NextConn(t).Done():
			case <-time.After(5 * time.Second):
				t.Fatal("connection kept open")
			}
		})
	}
}

// In exact mode a Connection field of Request.Header is not sent and does
// not close the connection, nor does a "close" in another field.
func TestH1PoolExactIgnoresHeaderClose(t *testing.T) {
	srv, base := h1Lab(t, false, nil)
	tr := transport(srv)
	defer tr.Close()
	ctx := order.WithExact(context.Background(), []order.Field{{Name: "Host", Value: "example.com"}, {Name: "X-Mode", Value: "close"}})
	for range 2 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
		req.Header.Set("Connection", "close")
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if c := srv.Accepted(); c != 1 {
		t.Fatalf("%d connections, want 1", c)
	}
}

// A connection the server closes while idle is detected before reuse: a
// request that cannot be replayed still succeeds, on a new connection.
func TestH1PoolServerClosedWhileIdle(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(map[bool]string{false: "TLS", true: "plain"}[plain], func(t *testing.T) {
			var n atomic.Int32
			srv, base := h1Lab(t, plain, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if n.Add(1) == 1 {
					// Keep-alive response, then the server closes.
					hijack(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", true)
					return
				}
				io.ReadAll(r.Body)
				io.WriteString(w, "ok")
			}))
			tr := transport(srv)
			defer tr.Close()
			fetch(t, tr, base+"/")
			<-srv.NextConn(t).Done()
			time.Sleep(20 * time.Millisecond) // the close reaches the client

			req, _ := http.NewRequest(http.MethodPost, base+"/", strings.NewReader("payload"))
			req.GetBody = nil // a replay is impossible
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			io.ReadAll(resp.Body)
			resp.Body.Close()
			if c := srv.Accepted(); c != 2 {
				t.Fatalf("%d connections, want 2", c)
			}
		})
	}
}

// The reused idle connection is lost after the request was written: a
// replayable request goes again on a new connection, another fails
// (section 6.3, same policy as HTTP/2). In exact mode the idempotency key
// counts only among the fields sent.
func TestH1PoolReplayAfterLostIdleConnection(t *testing.T) {
	host := order.Field{Name: "Host", Value: "example.com"}
	key := order.Field{Name: "idempotency-key", Value: "k1"}
	for _, tt := range []struct {
		name   string
		method string
		key    bool          // Idempotency-Key in req.Header
		exact  []order.Field // exact mode
		idem   bool          // Transport.Idempotent
		replay bool
	}{
		{name: "GET", method: http.MethodGet, replay: true},
		{name: "POST", method: http.MethodPost},
		{name: "POST of an idempotent transport", method: http.MethodPost, idem: true, replay: true},
		{name: "POST with key", method: http.MethodPost, key: true, replay: true},
		{name: "exact POST with key in Header", method: http.MethodPost, key: true, exact: []order.Field{host}},
		{name: "exact POST with key sent", method: http.MethodPost, exact: []order.Field{host, key}, replay: true},
		{name: "exact POST with X- key sent", method: http.MethodPost, exact: []order.Field{host, {Name: "X-Idempotency-Key", Value: "k1"}}, replay: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var n atomic.Int32
			srv, base := h1Lab(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if n.Add(1) == 2 {
					hijack(w, "", true) // lost without an answer
					return
				}
				io.WriteString(w, "ok")
			}))
			tr := transport(srv)
			tr.Idempotent = tt.idem
			defer tr.Close()
			fetch(t, tr, base+"/warm")
			ctx := context.Background()
			if tt.exact != nil {
				ctx = order.WithExact(ctx, tt.exact)
			}
			req, _ := http.NewRequestWithContext(ctx, tt.method, base+"/", nil)
			if tt.key {
				req.Header.Set("Idempotency-Key", "k1")
			}
			var got string
			resp, err := tr.RoundTrip(req)
			if err == nil {
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				got = string(b)
			}
			if !tt.replay {
				if err == nil {
					t.Fatal("request replayed after the connection was lost")
				}
				if c := srv.Accepted(); c != 1 {
					t.Fatalf("%d connections, want 1", c)
				}
				return
			}
			if err != nil || got != "ok" {
				t.Fatalf("got %q, %v", got, err)
			}
			if c := srv.Accepted(); c != 2 {
				t.Fatalf("%d connections, want 2", c)
			}
		})
	}
}

// An idle connection the server closes is closed on the client side at
// once, without waiting for the next request to find it.
func TestH1PoolIdleClosedByServerReleased(t *testing.T) {
	srv, base := h1Lab(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijack(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", true)
	}))
	closed := make(chan struct{})
	tr := transport(srv)
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &closeSignal{Conn: c, closed: closed}, nil
	}
	defer tr.Close()
	fetch(t, tr, base+"/")
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("connection closed by the server still open on the client")
	}
}

// closeSignal closes closed when the connection is closed.
type closeSignal struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeSignal) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// CloseIdleConnections closes idle HTTP/1.1 connections.
func TestH1PoolCloseIdleConnections(t *testing.T) {
	srv, base := h1Lab(t, false, nil)
	tr := transport(srv)
	defer tr.Close()
	fetch(t, tr, base+"/")
	tr.CloseIdleConnections()
	select {
	case <-srv.NextConn(t).Done():
	case <-time.After(5 * time.Second):
		t.Fatal("idle connection kept open")
	}
}

// An idle connection is closed when its idle timeout ends, and the next
// request dials; a request before the end reuses it and starts the period
// again.
func TestH1PoolIdleTimeout(t *testing.T) {
	t.Run("expires", func(t *testing.T) {
		srv, base := h1Lab(t, false, nil)
		tr := transport(srv)
		tr.IdleConnTimeout = 300 * time.Millisecond
		defer tr.Close()
		fetch(t, tr, base+"/")
		conn := srv.NextConn(t)
		select {
		case <-conn.Done():
			t.Fatal("closed before the idle timeout")
		case <-time.After(100 * time.Millisecond):
		}
		select {
		case <-conn.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("idle connection kept open")
		}
		fetch(t, tr, base+"/")
		if n := srv.Accepted(); n != 2 {
			t.Fatalf("%d connections, want 2", n)
		}
	})
	t.Run("restarted by reuse", func(t *testing.T) {
		srv, base := h1Lab(t, false, nil)
		tr := transport(srv)
		tr.IdleConnTimeout = 600 * time.Millisecond
		defer tr.Close()
		for i := range 3 {
			if i > 0 {
				time.Sleep(350 * time.Millisecond)
			}
			fetch(t, tr, base+"/")
		}
		if n := srv.Accepted(); n != 1 {
			t.Fatalf("%d connections, want 1", n)
		}
	})
}

// A 413 sent before the body ends, the connection then reset, is the
// response, as Chrome, over TLS too; the connection is not reused.
func TestH1EarlyAnswer(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(map[bool]string{false: "TLS", true: "plain"}[plain], func(t *testing.T) {
			srv, base := h1Lab(t, plain, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hijack(w, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 3\r\n\r\nbig", true)
			}))
			tr := transport(srv)
			defer tr.Close()
			body, err := send(context.Background(), tr, http.MethodPost, base+"/", bytes.NewReader(make([]byte, 64<<20)))
			if err != nil || body != "big" {
				t.Fatalf("body %q, %v", body, err)
			}
			select {
			case <-srv.NextConn(t).Done():
			case <-time.After(5 * time.Second):
				t.Fatal("connection kept open")
			}
		})
	}
}
