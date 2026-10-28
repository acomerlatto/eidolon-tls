package dispatch_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// A graceful GOAWAY that covers the stream, then the close of an idle
// connection, is a lost connection like a close without GOAWAY: a GET is
// sent again on a new connection, a POST is not (RFC 9113 section 6.8).
func TestGracefulGoAwayLostConnection(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			var conns atomic.Int32
			srv := lab.Start(t, lab.Options{H2Conn: func(c net.Conn) {
				first := conns.Add(1) == 1
				rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
					if !first || n == 1 {
						writeOK(fr, stream)
						return true
					}
					fr.WriteGoAway(stream, http2.ErrCodeNo, nil)
					c.Close()
					return false
				})(c)
			}})
			tr := transport(srv)
			defer tr.Close()
			if _, got, err := do(t, tr, http.MethodGet, "https://example.com/", ""); err != nil || got != "h2" {
				t.Fatalf("warm: %q %v", got, err)
			}
			body := ""
			if method == http.MethodPost {
				body = "payload"
			}
			_, got, err := do(t, tr, method, "https://example.com/", body)
			if method == http.MethodGet {
				if err != nil || got != "h2" || srv.Accepted() != 2 {
					t.Fatalf("%q %v after %d connections; want h2 on a new one", got, err, srv.Accepted())
				}
				return
			}
			var ge http2.GoAwayError
			if !errors.As(err, &ge) || srv.Accepted() != 1 {
				t.Fatalf("err = %v after %d connections; want the GOAWAY error, not sent again", err, srv.Accepted())
			}
		})
	}
}

// A request lost on an idle HTTP/2 connection is sent again once: when
// the replay is lost on another idle connection too, the request fails
// with ErrRetryBudget instead of a third attempt (RFC 9110 section 9.2.2).
func TestLostReplayOnce(t *testing.T) {
	goaway := make(chan struct{}) // X reached A, which sent GOAWAY
	closeA := make(chan struct{}) // Y is done: A may close
	var conns atomic.Int32
	srv := lab.Start(t, lab.Options{H2Conn: func(c net.Conn) {
		conn := conns.Add(1)
		rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
			switch {
			case n == 1:
				writeOK(fr, stream) // warm A, Y on B, or a third connection
				return true
			case conn == 1:
				fr.WriteGoAway(stream, http2.ErrCodeNo, nil)
				close(goaway)
				<-closeA
			}
			c.Close() // X on A, then its replay on B
			return false
		})(c)
	}})
	tr := transport(srv)
	defer tr.Close()
	if _, got, err := do(t, tr, http.MethodGet, "https://example.com/", ""); err != nil || got != "h2" {
		t.Fatalf("warm: %q %v", got, err)
	}
	errc := make(chan error, 1)
	go func() {
		_, _, err := do(t, tr, http.MethodGet, "https://example.com/x", "")
		errc <- err
	}()
	<-goaway
	// A is going away: Y opens B, and B is idle when A closes.
	if _, got, err := do(t, tr, http.MethodGet, "https://example.com/y", ""); err != nil || got != "h2" {
		t.Fatalf("Y: %q %v", got, err)
	}
	close(closeA)
	if err := <-errc; !errors.Is(err, dispatch.ErrRetryBudget) {
		t.Fatalf("X: err = %v, want ErrRetryBudget", err)
	}
	if n := srv.Accepted(); n != 2 {
		t.Fatalf("%d connections, want 2", n)
	}
}

// resetPreface fails the write of the HTTP/2 preface: the first write that
// starts with a TLS application_data record. The handshake writes
// Finished after ChangeCipherSpec, in a write that starts with 0x14.
type resetPreface struct {
	net.Conn
}

func (c *resetPreface) Write(p []byte) (int, error) {
	if len(p) > 0 && p[0] == 0x17 {
		c.Conn.Close()
		return 0, syscall.ECONNRESET
	}
	return c.Conn.Write(p)
}

// A new HTTP/2 connection lost before any request, whose preface could not
// be written or that closed before its first stream, sent nothing: the
// request dials again, whatever its method.
func TestNewConnectionLostBeforeRequest(t *testing.T) {
	t.Run("preface", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{H2Conn: rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
			writeOK(fr, stream)
			return true
		})})
		tr := transport(srv)
		var dials atomic.Int32
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, network, srv.Addr)
			if err == nil && dials.Add(1) == 1 {
				c = &resetPreface{Conn: c}
			}
			return c, err
		}
		defer tr.Close()
		if _, got, err := do(t, tr, http.MethodPost, "https://example.com/", "payload"); err != nil || got != "h2" {
			t.Fatalf("%q %v", got, err)
		}
		if n := dials.Load(); n != 2 {
			t.Fatalf("%d dials, want 2", n)
		}
	})
	t.Run("first stream", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{H2Conn: rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
			writeOK(fr, stream)
			return true
		})})
		tr := transport(srv)
		defer tr.Close()
		// The connection closes after the pool handed it to the request
		// and before its first stream.
		var once sync.Once
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			GotConn: func(ci httptrace.GotConnInfo) {
				once.Do(func() {
					ci.Conn.Close()
					time.Sleep(100 * time.Millisecond) // the read loop sees it
				})
			},
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com/", strings.NewReader("payload"))
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if n := srv.Accepted(); n != 2 {
			t.Fatalf("%d connections, want 2", n)
		}
	})
}
