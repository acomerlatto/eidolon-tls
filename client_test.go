package eidolon_test

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

func chromeSpec() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
	return &spec, err
}

// newClient returns a client whose connections all go to srv.
func newClient(t *testing.T, srv *lab.Server, opts ...eidolon.Option) eidolon.HttpClient {
	t.Helper()
	base := []eidolon.Option{
		eidolon.WithClientHello(chromeSpec),
		eidolon.WithRootCAs(srv.RootCAs),
		eidolon.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Addr)
		}),
	}
	c, err := eidolon.New(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestNewValidatesOptions(t *testing.T) {
	tests := []struct {
		name string
		opts []eidolon.Option
	}{
		{name: "no ClientHello"},
		{name: "nil ClientHello", opts: []eidolon.Option{eidolon.WithClientHello(nil)}},
		{name: "nil option", opts: []eidolon.Option{eidolon.WithClientHello(chromeSpec), nil}},
		{name: "nil pool", opts: []eidolon.Option{eidolon.WithClientHello(chromeSpec), eidolon.WithRootCAs(nil)}},
		{name: "negative timeout", opts: []eidolon.Option{eidolon.WithClientHello(chromeSpec), eidolon.WithTimeout(-time.Second)}},
		{name: "nil dialer", opts: []eidolon.Option{eidolon.WithClientHello(chromeSpec), eidolon.WithDialContext(nil)}},
		{name: "zero connections per host", opts: []eidolon.Option{eidolon.WithClientHello(chromeSpec), eidolon.WithMaxConnsPerHost(0)}},
		{name: "zero idle timeout", opts: []eidolon.Option{eidolon.WithClientHello(chromeSpec), eidolon.WithIdleConnTimeout(0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := eidolon.New(tt.opts...)
			if !errors.Is(err, eidolon.ErrConfig) || c != nil {
				t.Fatalf("New = %v, %v; want nil, ErrConfig", c, err)
			}
		})
	}
}

// send makes the same ordered request with do and returns the bytes the lab
// received after the handshake.
func send(t *testing.T, srv *lab.Server, do func(*http.Request) (*http.Response, error)) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/same", nil)
	req.Header[eidolon.HeaderOrderKey] = []string{"host", "user-agent", "accept", "x-a"}
	req.Header.Set("X-A", "a")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "eidolon-test")
	resp, err := do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.TLS == nil {
		t.Fatal("Response.TLS is nil")
	}
	return srv.NextConn(t).Bytes()
}

// Do and an http.Client built on Transport() take the same path (R1): the
// server receives the same bytes.
func TestDoAndTransportSamePath(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	c := newClient(t, srv)
	viaDo := send(t, srv, c.Do)
	c.CloseIdleConnections() // the second request on a connection of its own
	viaTransport := send(t, srv, (&http.Client{Transport: c.Transport()}).Do)
	if string(viaDo) != string(viaTransport) {
		t.Fatalf("Do sent %q\nTransport sent %q", viaDo, viaTransport)
	}
	want := "GET /same HTTP/1.1\r\nHost: example.com\r\nUser-Agent: eidolon-test\r\nAccept: */*\r\nX-A: a\r\n\r\n"
	if string(viaDo) != want {
		t.Fatalf("sent %q, want %q", viaDo, want)
	}
}

func TestShortcuts(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	c := newClient(t, srv)
	for _, tt := range []struct {
		name string
		do   func() (*http.Response, error)
		line string
	}{
		{"Get", func() (*http.Response, error) { return c.Get("https://example.com/g") }, "GET /g HTTP/1.1"},
		{"Head", func() (*http.Response, error) { return c.Head("https://example.com/h") }, "HEAD /h HTTP/1.1"},
		{"Post", func() (*http.Response, error) {
			return c.Post("https://example.com/p", "text/plain", strings.NewReader("body"))
		}, "POST /p HTTP/1.1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.do()
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			c.CloseIdleConnections() // one connection per subtest
			if got := string(srv.NextConn(t).Bytes()); !strings.HasPrefix(got, tt.line+"\r\n") {
				t.Fatalf("sent %q, want request line %q", got, tt.line)
			}
		})
	}
}

// The order keys reach the HTTP/2 engine through the public API.
func TestHeaderOrderKeysH2(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	c := newClient(t, srv)
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/o", nil)
	req.Header[eidolon.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	req.Header[eidolon.HeaderOrderKey] = []string{"x-b", "x-a"}
	req.Header.Set("X-A", "a")
	req.Header.Set("X-B", "b")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	frames, err := srv.NextConn(t).H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range frames {
		if f.Type == "HEADERS" {
			for _, h := range f.Headers {
				names = append(names, h.Name)
			}
			break
		}
	}
	if len(names) < 6 || !slices.Equal(names[:6], []string{":method", ":authority", ":scheme", ":path", "x-b", "x-a"}) {
		t.Fatalf("header order = %q", names)
	}
}

func TestErrALPN(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"spdy/3"}})
	c := newClient(t, srv, eidolon.WithClientHello(func() (*utls.ClientHelloSpec, error) {
		spec, err := chromeSpec()
		for _, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"spdy/3"}
			}
		}
		return spec, err
	}))
	_, err := c.Get("https://example.com/")
	if !errors.Is(err, eidolon.ErrALPN) {
		t.Fatalf("err = %v, want ErrALPN", err)
	}
}

func TestTimeout(t *testing.T) {
	srv := lab.Start(t, lab.Options{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})})
	c := newClient(t, srv, eidolon.WithTimeout(200*time.Millisecond))
	start := time.Now()
	_, err := c.Get("https://example.com/slow")
	// http.Client arms a context deadline and a timer for the same instant
	// when the transport is not its own; whichever fires first decides the
	// message, so only Timeout() is checked.
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("returned after %v", d)
	}
}

// The pool is copied: changing it after New does not change the client.
func TestRootCAsCopied(t *testing.T) {
	srv := lab.Start(t, lab.Options{})
	pool := x509.NewCertPool()
	c := newClient(t, srv, eidolon.WithRootCAs(pool))
	pool.AddCert(srv.Certificate)
	var unknown x509.UnknownAuthorityError
	if _, err := c.Get("https://example.com/"); !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want an unknown authority error", err)
	}
}

// Close interrupts a response in progress and refuses new requests, through
// Do and through Transport().
func TestClose(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			srv := lab.Start(t, lab.Options{
				NextProtos: []string{proto},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, "partial")
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
					}
				}),
			})
			c := newClient(t, srv)
			resp, err := c.Get("https://example.com/stream")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			buf := make([]byte, len("partial"))
			if _, err := io.ReadFull(resp.Body, buf); err != nil {
				t.Fatal(err)
			}

			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			readErr := make(chan error, 1)
			go func() {
				_, err := io.ReadAll(resp.Body)
				readErr <- err
			}()
			select {
			case err := <-readErr:
				if err == nil {
					t.Fatal("body read ended without error after Close")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close did not interrupt the response")
			}

			if _, err := c.Get("https://example.com/again"); !errors.Is(err, eidolon.ErrClosed) {
				t.Fatalf("Do after Close: %v, want ErrClosed", err)
			}
			if _, err := (&http.Client{Transport: c.Transport()}).Get("https://example.com/again"); !errors.Is(err, eidolon.ErrClosed) {
				t.Fatalf("Transport after Close: %v, want ErrClosed", err)
			}
		})
	}
}

// CloseIdleConnections never interrupts a response in progress (R4).
func TestCloseIdleConnectionsKeepsActiveResponse(t *testing.T) {
	release := make(chan struct{})
	srv := lab.Start(t, lab.Options{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "first;")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "second")
	})})
	c := newClient(t, srv)
	resp, err := c.Get("https://example.com/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	c.CloseIdleConnections()
	close(release)
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "first;second" {
		t.Fatalf("body = %q, %v", body, err)
	}
}

// The connection options reach the HTTP/1.1 pool: one connection serves
// two concurrent requests in turn, and is closed once idle for the timeout.
func TestConnectionOptions(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	})})
	c := newClient(t, srv, eidolon.WithMaxConnsPerHost(1), eidolon.WithIdleConnTimeout(300*time.Millisecond))
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			resp, err := c.Get("https://example.com/")
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		})
	}
	wg.Wait()
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
	select {
	case <-srv.NextConn(t).Done():
	case <-time.After(5 * time.Second):
		t.Fatal("idle connection kept open")
	}
}
