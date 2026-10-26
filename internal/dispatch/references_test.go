package dispatch_test

// Scenarios from the reference test cut (M0-E, annex A6), reproduced on the
// lab because third-party code is not run locally. Scenarios that need the
// M1 pool are listed in the roadmap instead.

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// tls-client alpn_change_test: the server of one origin negotiates h2 on
// one connection and http/1.1 on the next. Each connection goes to the
// engine of its own ALPN, and no request is written in the wrong protocol.
func TestReferenceALPNChangeBetweenConnections(t *testing.T) {
	for _, order := range [][]string{{"h2", "http/1.1"}, {"http/1.1", "h2"}} {
		t.Run(strings.Join(order, "->"), func(t *testing.T) {
			first := lab.Start(t, lab.Options{NextProtos: []string{order[0]}})
			second := lab.Start(t, lab.Options{NextProtos: []string{order[1]}})
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
			client := &http.Client{Transport: tr}

			for i, srv := range []*lab.Server{first, second} {
				resp := get(t, client, "https://example.com/x")
				want := order[i]
				if got := resp.TLS.NegotiatedProtocol; got != want {
					t.Fatalf("request %d: ALPN %q, want %q", i, got, want)
				}
				if (resp.ProtoMajor == 2) != (want == "h2") {
					t.Fatalf("request %d: %s over ALPN %q", i, resp.Proto, want)
				}
				c := srv.NextConn(t)
				if want == "h2" {
					if _, err := c.H2Frames(); err != nil {
						t.Fatalf("request %d: h2 connection did not carry HTTP/2: %v", i, err)
					}
				} else if !strings.HasPrefix(string(c.Bytes()), "GET /x HTTP/1.1\r\n") {
					t.Fatalf("request %d: http/1.1 connection carried %q", i, c.Bytes())
				}
			}
		})
	}
}

// AzureTLS, stalled handshake: a server that accepts TCP and never answers
// ends the request at the context deadline, with the context error.
func TestReferenceStalledHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	tr := &dispatch.Transport{
		Spec: chromeSpec,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ln.Addr().String())
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	start := time.Now()
	_, err = tr.RoundTrip(req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("returned after %v", d)
	}
}

// AzureTLS, streaming response: headers and the first part of the body
// arrive before the server finishes, and cancelling the context afterwards
// stops the body read.
func TestReferenceStreamingResponse(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			srv := lab.Start(t, lab.Options{
				NextProtos: []string{proto},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, "first;")
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
					}
				}),
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/stream", nil)

			type result struct {
				resp *http.Response
				err  error
			}
			done := make(chan result, 1)
			go func() {
				resp, err := transport(srv).RoundTrip(req)
				done <- result{resp, err}
			}()
			var r result
			select {
			case r = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("headers did not arrive before the body ended")
			}
			if r.err != nil {
				t.Fatal(r.err)
			}
			defer r.resp.Body.Close()

			buf := make([]byte, len("first;"))
			if _, err := io.ReadFull(r.resp.Body, buf); err != nil || string(buf) != "first;" {
				t.Fatalf("first part = %q, %v", buf, err)
			}

			cancel()
			readErr := make(chan error, 1)
			go func() {
				_, err := io.ReadAll(r.resp.Body)
				readErr <- err
			}()
			select {
			case err := <-readErr:
				if err == nil {
					t.Fatal("body read ended without error after cancel")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("body read did not stop after cancel")
			}
		})
	}
}
