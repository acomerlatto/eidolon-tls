package eidolon_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// expiredCertificate returns a certificate for the lab name that expired
// an hour ago.
func expiredCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: lab.ServerName},
		DNSNames:              []string{lab.ServerName},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// A refused certificate is ErrCertificate, with the crypto/x509 cause
// in the chain, and no request reaches the server.
func TestErrCertificate(t *testing.T) {
	cert, leaf := expiredCertificate(t)
	expiredPool := x509.NewCertPool()
	expiredPool.AddCert(leaf)
	tests := []struct {
		name  string
		opts  lab.Options
		url   string
		roots *x509.CertPool
		cause func(error) bool
	}{
		{"unknown authority", lab.Options{}, "https://example.com/", x509.NewCertPool(), func(err error) bool {
			var e x509.UnknownAuthorityError
			return errors.As(err, &e)
		}},
		{"wrong name", lab.Options{}, "https://other.example/", nil, func(err error) bool {
			var e x509.HostnameError
			return errors.As(err, &e)
		}},
		{"expired", lab.Options{TLS: func(c *tls.Config) { c.Certificates = []tls.Certificate{cert} }}, "https://example.com/", expiredPool, func(err error) bool {
			var e x509.CertificateInvalidError
			return errors.As(err, &e) && e.Reason == x509.Expired
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			tt.opts.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) })
			srv := lab.Start(t, tt.opts)
			var opts []eidolon.Option
			if tt.roots != nil {
				opts = append(opts, eidolon.WithRootCAs(tt.roots))
			}
			c := newClient(t, srv, opts...)
			_, err := c.Get(tt.url)
			if !errors.Is(err, eidolon.ErrCertificate) || !tt.cause(err) {
				t.Fatalf("err = %v, want ErrCertificate with the x509 cause", err)
			}
			if n := requests.Load(); n != 0 {
				t.Fatalf("%d requests reached the server", n)
			}
		})
	}
}

// hijacked answers every HTTP/1.1 request with raw, then closes.
func hijacked(raw string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			panic(err)
		}
		buf.WriteString(raw)
		buf.Flush()
		c.Close()
	})
}

// HTTP/1.1 responses that cannot be read are ErrMalformedResponse; a
// repeated identical Content-Length is accepted, as in net/http and
// Chrome; a connection lost in the middle is not malformed.
func TestErrMalformedResponse(t *testing.T) {
	early := "HTTP/1.1 103 Early Hints\r\n\r\n"
	tests := []struct {
		name string
		raw  string
		want error // nil: the body "ok"
	}{
		{"bad status code", "HTTP/1.1 2x0 OK\r\nContent-Length: 2\r\n\r\nok", eidolon.ErrMalformedResponse},
		{"bad version", "HTTX/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", eidolon.ErrMalformedResponse},
		{"header without colon", "HTTP/1.1 200 OK\r\nBroken\r\nContent-Length: 2\r\n\r\nok", eidolon.ErrMalformedResponse},
		{"conflicting Content-Length", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok", eidolon.ErrMalformedResponse},
		{"six 1xx", strings.Repeat(early, 6) + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", eidolon.ErrMalformedResponse},
		{"repeated Content-Length", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok", nil},
		{"lost in the headers", "HTTP/1.1 200 OK\r\nX-A: 1\r\n", io.ErrUnexpectedEOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: hijacked(tt.raw)})
			c := newClient(t, srv)
			resp, err := c.Get("https://example.com/")
			if tt.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if string(body) != "ok" {
					t.Fatalf("body %q", body)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if tt.want != eidolon.ErrMalformedResponse && errors.Is(err, eidolon.ErrMalformedResponse) {
				t.Fatalf("err = %v: a lost connection is not malformed", err)
			}
		})
	}
}

// rawH2Conn serves an h2 connection with answer for each request.
func rawH2Conn(answer func(fr *http2.Framer, stream uint32)) func(net.Conn) {
	return func(c net.Conn) {
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
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					fr.WriteSettingsAck()
				}
			case *http2.HeadersFrame:
				answer(fr, f.StreamID)
			}
		}
	}
}

// Response headers over 256 KiB are ErrHeaderTooLarge over both protocols.
func TestErrHeaderTooLarge(t *testing.T) {
	big := strings.Repeat("a", 300<<10)
	t.Run("http/1.1", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: hijacked("HTTP/1.1 200 OK\r\nX-Big: " + big + "\r\nContent-Length: 2\r\n\r\nok")})
		if _, err := newClient(t, srv).Get("https://example.com/"); !errors.Is(err, eidolon.ErrHeaderTooLarge) {
			t.Fatalf("err = %v, want ErrHeaderTooLarge", err)
		}
	})
	t.Run("h2", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{H2Conn: rawH2Conn(func(fr *http2.Framer, stream uint32) {
			var block bytes.Buffer
			enc := hpack.NewEncoder(&block)
			enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			enc.WriteField(hpack.HeaderField{Name: "x-big", Value: big})
			b := block.Bytes()
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: b[:16<<10]})
			for b = b[16<<10:]; len(b) > 0; {
				n := min(16<<10, len(b))
				fr.WriteContinuation(stream, n == len(b), b[:n])
				b = b[n:]
			}
		})})
		if _, err := newClient(t, srv).Get("https://example.com/"); !errors.Is(err, eidolon.ErrHeaderTooLarge) {
			t.Fatalf("err = %v, want ErrHeaderTooLarge", err)
		}
	})
}

// A request refused every time is ErrRetryBudget after two retries, with
// the refusal in the chain.
func TestErrRetryBudget(t *testing.T) {
	var attempts atomic.Int32
	srv := lab.Start(t, lab.Options{H2Conn: rawH2Conn(func(fr *http2.Framer, stream uint32) {
		attempts.Add(1)
		fr.WriteRSTStream(stream, http2.ErrCodeRefusedStream)
	})})
	_, err := newClient(t, srv).Get("https://example.com/")
	var se http2.StreamError
	if !errors.Is(err, eidolon.ErrRetryBudget) || !errors.As(err, &se) || se.Code != http2.ErrCodeRefusedStream {
		t.Fatalf("err = %v, want ErrRetryBudget with REFUSED_STREAM", err)
	}
	if n := attempts.Load(); n != 3 {
		t.Fatalf("%d attempts, want 3", n)
	}
}

// The context error is kept, for errors.Is, wherever the request is: in
// the dial, in the handshake, or waiting for the response headers.
func TestContextErrorKept(t *testing.T) {
	stall := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	// A listener that accepts and never answers the ClientHello.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	stages := []struct {
		name  string
		opts  lab.Options
		dial  func(ctx context.Context, srv *lab.Server) (net.Conn, error)
		cause error
	}{
		{"dial", lab.Options{}, func(ctx context.Context, _ *lab.Server) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, nil},
		{"handshake", lab.Options{}, func(ctx context.Context, _ *lab.Server) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", silent.Addr().String())
		}, nil},
		{"headers/h2", lab.Options{NextProtos: []string{"h2"}, Handler: stall}, nil, nil},
		{"headers/http1.1", lab.Options{NextProtos: []string{"http/1.1"}, Handler: stall}, nil, nil},
	}
	for _, st := range stages {
		for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
			t.Run(st.name+"/"+want.Error(), func(t *testing.T) {
				srv := lab.Start(t, st.opts)
				var opts []eidolon.Option
				if st.dial != nil {
					opts = append(opts, eidolon.WithDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) {
						return st.dial(ctx, srv)
					}))
				}
				c := newClient(t, srv, opts...)
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				defer cancel()
				if want == context.Canceled {
					ctx, cancel = context.WithCancel(context.Background())
					time.AfterFunc(200*time.Millisecond, cancel)
				}
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
				start := time.Now()
				_, err := c.Do(req)
				if !errors.Is(err, want) {
					t.Fatalf("err = %v, want %v", err, want)
				}
				if d := time.Since(start); d > 5*time.Second {
					t.Fatalf("returned after %v", d)
				}
			})
		}
	}
}

// CR or LF in a header name or value is refused before anything is sent,
// over both protocols.
func TestHeaderInjectionRefused(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		for _, tt := range []struct {
			name         string
			field, value string
		}{
			{"value", "X-A", "1\r\nX-Injected: 1"},
			{"value LF", "X-A", "1\nX-Injected: 1"},
			{"name", "X-A\r\nX-Injected", "1"},
		} {
			t.Run(proto+"/"+tt.name, func(t *testing.T) {
				var requests atomic.Int32
				srv := lab.Start(t, lab.Options{NextProtos: []string{proto}, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					requests.Add(1)
				})})
				c := newClient(t, srv)
				req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
				req.Header[tt.field] = []string{tt.value}
				if resp, err := c.Do(req); err == nil {
					resp.Body.Close()
					t.Fatal("request sent")
				}
				if n := requests.Load(); n != 0 {
					t.Fatalf("%d requests reached the server", n)
				}
				// The client still works.
				if resp, err := c.Get("https://example.com/"); err != nil {
					t.Fatal(err)
				} else {
					resp.Body.Close()
				}
			})
		}
	}
}
