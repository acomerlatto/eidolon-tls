package eidolon_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

var chrome = eidolon.WithProfile(eidolon.Chrome156Linux())

// noLeaks fails t if goroutines started after the call outlive the test
// and its later cleanups, which close the servers first.
func noLeaks(t *testing.T) {
	t.Helper()
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
}

// closedConns waits for every connection the server accepted to be closed
// by the client.
func closedConns(t *testing.T, srv *lab.Server) {
	t.Helper()
	for range srv.Accepted() {
		select {
		case <-srv.NextConn(t).Done():
		case <-time.After(5 * time.Second):
			t.Fatal("a connection stays open after Close")
		}
	}
}

// streamingHandler writes a header and then the body in chunks until the
// request ends.
var streamingHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	chunk := []byte(strings.Repeat("x", 16<<10))
	for {
		if _, err := w.Write(chunk); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Millisecond):
		}
	}
})

// A response abandoned in any state leaves no goroutine or connection
// once the client is closed: a body closed before its end, a request
// canceled while its body streams, a connection broken mid-body, and
// Close with requests in flight, or waiting for a connection. Over HTTP/2
// and HTTP/1.1.
func TestNoLeaksResponses(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			t.Run("body closed early", func(t *testing.T) {
				noLeaks(t)
				srv := lab.Start(t, lab.Options{NextProtos: []string{proto}, Handler: streamingHandler})
				c := profileClient(t, srv, chrome)
				for range 3 {
					resp, err := c.Get("https://example.com/")
					if err != nil {
						t.Fatal(err)
					}
					io.CopyN(io.Discard, resp.Body, 1000)
					resp.Body.Close()
				}
				c.Close()
				closedConns(t, srv)
			})
			t.Run("canceled while streaming", func(t *testing.T) {
				noLeaks(t)
				srv := lab.Start(t, lab.Options{NextProtos: []string{proto}, Handler: streamingHandler})
				c := profileClient(t, srv, chrome)
				ctx, cancel := context.WithCancel(context.Background())
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
				resp, err := c.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				io.CopyN(io.Discard, resp.Body, 1000)
				cancel()
				if _, err := io.Copy(io.Discard, resp.Body); err == nil {
					t.Error("body read to its end after the cancel")
				}
				resp.Body.Close()
				c.Close()
				closedConns(t, srv)
			})
			t.Run("connection broken", func(t *testing.T) {
				noLeaks(t)
				opts := lab.Options{NextProtos: []string{proto}}
				if proto == "h2" {
					opts.H2Conn = func(conn net.Conn) { conn.Close() }
				} else {
					opts.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						conn, buf, err := http.NewResponseController(w).Hijack()
						if err != nil {
							return
						}
						buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nshort")
						buf.Flush()
						conn.Close()
					})
				}
				srv := lab.Start(t, opts)
				c := profileClient(t, srv, chrome)
				if resp, err := c.Get("https://example.com/"); err == nil {
					if _, err := io.Copy(io.Discard, resp.Body); err == nil {
						t.Error("short body read without error")
					}
					resp.Body.Close()
				}
				c.Close()
			})
			t.Run("Close with requests in flight", func(t *testing.T) {
				noLeaks(t)
				arrived := make(chan struct{}, 8)
				srv := lab.Start(t, lab.Options{NextProtos: []string{proto}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					arrived <- struct{}{}
					<-r.Context().Done()
				})})
				// Over HTTP/1.1, two requests wait for a connection.
				c := profileClient(t, srv, chrome, eidolon.WithMaxConnsPerHost(2))
				var wg sync.WaitGroup
				for range 4 {
					wg.Go(func() {
						if resp, err := c.Get("https://example.com/"); err == nil {
							resp.Body.Close()
							t.Error("request answered")
						}
					})
				}
				served := 4
				if proto == "http/1.1" {
					served = 2
				}
				for range served {
					<-arrived
				}
				c.Close()
				wg.Wait()
				closedConns(t, srv)
			})
		})
	}
}

// A request canceled while its connection is being opened leaves nothing
// behind: during the lookup of the HTTPS record, the TCP dial and the TLS
// handshake.
func TestNoLeaksCanceledDial(t *testing.T) {
	silent := func(t *testing.T) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var conns []net.Conn
		var mu sync.Mutex
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				conns = append(conns, c)
				mu.Unlock()
			}
		}()
		t.Cleanup(func() {
			ln.Close()
			<-done
			for _, c := range conns {
				c.Close()
			}
		})
		return ln.Addr().String()
	}
	for _, tt := range []struct {
		name string
		opts func(t *testing.T) []eidolon.Option
	}{
		{"lookup", func(t *testing.T) []eidolon.Option {
			cert, err := lab.NewCertificate(time.Hour, dohHost)
			if err != nil {
				t.Fatal(err)
			}
			srv := lab.Start(t, lab.Options{Certificate: &cert, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-r.Context().Done() // the DoH server never answers
			})})
			return []eidolon.Option{chrome, eidolon.WithRootCAs(srv.RootCAs),
				eidolon.WithDoH("https://"+dohHost+"/dns-query{?dns}", "127.0.0.1"),
				eidolon.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, srv.Addr)
				})}
		}},
		{"dial", func(t *testing.T) []eidolon.Option {
			return []eidolon.Option{chrome, eidolon.WithDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			})}
		}},
		{"handshake", func(t *testing.T) []eidolon.Option {
			addr := silent(t)
			return []eidolon.Option{chrome, eidolon.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			})}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			noLeaks(t)
			c, err := eidolon.New(tt.opts(t)...)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://origin.example/", nil)
			if resp, err := c.Do(req); !errors.Is(err, context.DeadlineExceeded) {
				if err == nil {
					resp.Body.Close()
				}
				t.Errorf("error %v, want the deadline", err)
			}
			c.Close()
		})
	}
}

// Clients made, used and closed concurrently, with CloseIdleConnections
// among the requests and Close while they run: no data race (go test
// -race), no goroutine or connection left.
func TestConcurrentUseAndClose(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			noLeaks(t)
			srv := lab.Start(t, lab.Options{NextProtos: []string{proto}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, strings.Repeat("x", 4096))
			})})
			dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, srv.Addr)
			}
			var clients sync.WaitGroup
			for range 4 {
				clients.Go(func() {
					c, err := eidolon.New(chrome, eidolon.WithRootCAs(srv.RootCAs), eidolon.WithDialContext(dial))
					if err != nil {
						t.Error(err)
						return
					}
					var reqs sync.WaitGroup
					for i := range 16 {
						reqs.Go(func() {
							if i%5 == 0 {
								c.CloseIdleConnections()
							}
							resp, err := c.Get("https://example.com/")
							if err != nil {
								return // closed under it
							}
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
						})
					}
					time.Sleep(time.Millisecond)
					c.Close()
					reqs.Wait()
					if _, err := c.Get("https://example.com/"); !errors.Is(err, eidolon.ErrClosed) {
						t.Errorf("request after Close: %v, want ErrClosed", err)
					}
				})
			}
			clients.Wait()
			closedConns(t, srv)
		})
	}
}

// A body closed early releases its HTTP/2 stream: with two streams allowed
// by the server, ten requests whose bodies are closed before their end go
// over the one connection without waiting.
func TestH2StreamsReleased(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}, Handler: streamingHandler, H2: func(s *http2.Server) { s.MaxConcurrentStreams = 2 }})
	c := profileClient(t, srv, chrome)
	for range 10 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
		resp, err := c.Do(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		io.CopyN(io.Discard, resp.Body, 1000)
		resp.Body.Close()
		cancel()
	}
	if n := srv.Accepted(); n != 1 {
		t.Errorf("%d connections, want 1", n)
	}
}

// WithMaxConns bounds the connections of the client: over the limit, a
// request to another host closes the idle connection.
func TestMaxConns(t *testing.T) {
	cert, err := lab.NewCertificate(time.Hour, "a.test", "b.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{Certificate: &cert, NextProtos: []string{"http/1.1"}})
	c := profileClient(t, srv, chrome, eidolon.WithMaxConns(1))
	for _, u := range []string{"https://a.test/", "https://b.test/"} {
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	select {
	case <-srv.NextConn(t).Done():
	case <-time.After(5 * time.Second):
		t.Error("the idle connection of a.test stays open over the limit")
	}
}
