package dispatch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// A dial whose ClientHello cannot be built gives its slot back.
func TestMaxConnsBadSpec(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	calls := 0
	tr := &Transport{
		Spec: func() (*utls.ClientHelloSpec, error) {
			if calls++; calls == 1 {
				return nil, errors.New("no spec")
			}
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
			return &spec, err
		},
		TLS: &utls.Config{RootCAs: srv.RootCAs},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Addr)
		},
		MaxConns: 1,
	}
	defer tr.Close()
	for i := range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
		resp, err := tr.RoundTrip(req)
		if err == nil {
			resp.Body.Close()
		}
		cancel()
		if (err == nil) != (i == 1) {
			t.Fatalf("request %d: %v", i, err)
		}
	}
}

// The wait for a slot of MaxConns does not count in dialTimeout.
func TestMaxConnsWaitOutsideDialTimeout(t *testing.T) {
	defer func(d time.Duration) { dialTimeout = d }(dialTimeout)
	dialTimeout = 200 * time.Millisecond
	cert, err := lab.NewCertificate(time.Hour, "a.test", "b.test")
	if err != nil {
		t.Fatal(err)
	}
	arrived := make(chan struct{}, 1)
	srv := lab.Start(t, lab.Options{Certificate: &cert, NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			arrived <- struct{}{}
			time.Sleep(400 * time.Millisecond)
		}
		io.WriteString(w, "ok")
	})})
	tr := &Transport{
		Spec: func() (*utls.ClientHelloSpec, error) {
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
			return &spec, err
		},
		TLS: &utls.Config{RootCAs: srv.RootCAs},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Addr)
		},
		MaxConns: 1,
	}
	defer tr.Close()
	get := func(url string) error {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		return resp.Body.Close()
	}
	slow := make(chan error, 1)
	go func() { slow <- get("https://a.test/slow") }()
	<-arrived
	if err := get("https://b.test/"); err != nil {
		t.Fatalf("after waiting for a slot: %v", err)
	}
	if err := <-slow; err != nil {
		t.Fatal(err)
	}
}
