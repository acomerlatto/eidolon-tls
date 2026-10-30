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

// waitFor fails t if cond, called under no lock, is not true within five
// seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// A request that joins a shared dial after its last waiter left, while
// the dial ends its wait for a slot, starts another dial instead of failing
// with the cancellation of that wait.
func TestMaxConnsJoinAbandonedDial(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
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
	l := tr.limiter()
	held, err := l.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	get := func(ctx context.Context) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		return resp.Body.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { first <- get(ctx) }()
	waitFor(t, "the shared dial to wait for a slot", l.stalled)

	// The dial cannot end its wait while l.mu is held.
	l.mu.Lock()
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		l.mu.Unlock()
		t.Fatalf("first request: %v, want its cancellation", err)
	}
	second := make(chan error, 1)
	go func() { second <- get(context.Background()) }()
	joined := func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		for _, call := range tr.dialing {
			return call.waiters == 1
		}
		return false
	}
	for deadline := time.Now().Add(5 * time.Second); !joined(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			l.mu.Unlock()
			t.Fatal("the second request did not join the shared dial")
		}
	}
	l.mu.Unlock()

	waitFor(t, "the second request to wait for a slot", l.stalled)
	held.release()
	if err := <-second; err != nil {
		t.Fatalf("second request: %v", err)
	}
}

// The HTTP/2 engines of the children of NewConnPerRequest, which close
// their connection with their response, do not join the limit: it would
// keep one per request.
func TestMaxConnsPerRequestH2(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
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
		MaxConns:          2,
		NewConnPerRequest: true,
	}
	defer tr.Close()
	for range 5 {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.ProtoMajor != 2 {
			t.Fatalf("HTTP/%d, want HTTP/2", resp.ProtoMajor)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	l := tr.limiter()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.h2) != 0 {
		t.Errorf("%d engines under the limit, want 0", len(l.h2))
	}
}
