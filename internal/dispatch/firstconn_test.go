package dispatch_test

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// gatedDialer sends every connection to addr once the gate opens, and
// counts the dials. started receives one value per dial.
type gatedDialer struct {
	addr    func(n int32) string
	gate    chan struct{}
	dials   atomic.Int32
	started chan struct{}
}

func newGatedDialer(addr string) *gatedDialer {
	return &gatedDialer{
		addr:    func(int32) string { return addr },
		gate:    make(chan struct{}),
		started: make(chan struct{}, 64),
	}
}

func (d *gatedDialer) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	n := d.dials.Add(1)
	d.started <- struct{}{}
	select {
	case <-d.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.addr(n))
}

func (d *gatedDialer) transport(roots *x509.CertPool) *dispatch.Transport {
	return &dispatch.Transport{
		Spec:        chromeSpec,
		TLS:         &utls.Config{RootCAs: roots},
		DialContext: d.dial,
	}
}

// get sends a GET with ctx and reads the body.
func getCtx(ctx context.Context, rt http.RoundTripper, url string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	return err
}

// concurrently runs n GETs while the dial is held, then opens the gate.
func concurrently(t *testing.T, n int, tr http.RoundTripper, d *gatedDialer) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() { errs <- getCtx(context.Background(), tr, "https://example.com/") })
	}
	<-d.started
	time.Sleep(50 * time.Millisecond) // let the others join or dial
	close(d.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

// Concurrent requests to an origin of unknown protocol wait for the first
// connection; it negotiates h2 and all of them multiplex on it.
func TestFirstConnH2SharedDial(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	d := newGatedDialer(srv.Addr)
	tr := d.transport(srv.RootCAs)
	defer tr.Close()
	concurrently(t, 5, tr, d)
	if n := d.dials.Load(); n != 1 {
		t.Fatalf("%d dials, want 1", n)
	}
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
}

// When the first connection negotiates http/1.1, one waiter takes it and
// the others dial their own: every connection carries one request, none is
// left unused. The server answers once all of them arrived, so no request
// finds an idle connection to reuse.
func TestFirstConnHTTP1OwnConnections(t *testing.T) {
	const n = 5
	var arrived sync.WaitGroup
	arrived.Add(n)
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived.Done()
		arrived.Wait()
		io.WriteString(w, "ok")
	})})
	d := newGatedDialer(srv.Addr)
	tr := d.transport(srv.RootCAs)
	defer tr.Close()
	concurrently(t, n, tr, d)
	if c := srv.Accepted(); c != n {
		t.Fatalf("%d connections, want %d", c, n)
	}
	for range n {
		if raw := string(srv.NextConn(t).Bytes()); strings.Count(raw, " HTTP/1.1\r\n") != 1 {
			t.Fatalf("connection carried %q, want one request", raw)
		}
	}
}

// httpcloak h2_dial_waiter_ctx_test: against a handshake that stalls, a
// request waiting for the shared dial ends at its own deadline, not at the
// leader's.
func TestFirstConnWaiterOwnContext(t *testing.T) {
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
			defer c.Close() // accepts TCP, never answers the ClientHello
		}
	}()
	var dials atomic.Int32
	started := make(chan struct{}, 4)
	tr := &dispatch.Transport{
		Spec: chromeSpec,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dials.Add(1)
			started <- struct{}{}
			var nd net.Dialer
			return nd.DialContext(ctx, network, ln.Addr().String())
		},
	}
	defer tr.Close()

	leaderCtx, cancelLeader := context.WithTimeout(context.Background(), time.Second)
	defer cancelLeader()
	leader := make(chan error, 1)
	go func() { leader <- getCtx(leaderCtx, tr, "https://example.com/") }()
	<-started

	waiterCtx, cancelWaiter := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelWaiter()
	start := time.Now()
	err = getCtx(waiterCtx, tr, "https://example.com/")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter: %v, want its own deadline", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("waiter returned after %v", d)
	}
	if err := <-leader; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("leader: %v, want its own deadline", err)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("%d dials, want 1 shared", n)
	}
}

// The request that started the dial gives up; the dial is not its own, so
// a request waiting for it still gets the connection.
func TestFirstConnLeaderCanceledWaiterContinues(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	d := newGatedDialer(srv.Addr)
	tr := d.transport(srv.RootCAs)
	defer tr.Close()

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leader := make(chan error, 1)
	go func() { leader <- getCtx(leaderCtx, tr, "https://example.com/") }()
	<-d.started
	waiter := make(chan error, 1)
	go func() { waiter <- getCtx(context.Background(), tr, "https://example.com/") }()
	time.Sleep(50 * time.Millisecond)
	cancelLeader()
	if err := <-leader; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader: %v, want context.Canceled", err)
	}
	close(d.gate)
	if err := <-waiter; err != nil {
		t.Fatalf("waiter: %v", err)
	}
	if n := d.dials.Load(); n != 1 {
		t.Fatalf("%d dials, want 1", n)
	}
}

// R2: a dial that ends after every waiter left is not wasted when it
// negotiates h2: the connection enters the pool and the next request uses
// it.
func TestFirstConnLateH2EntersPool(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	d := newGatedDialer(srv.Addr)
	tr := d.transport(srv.RootCAs)
	defer tr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- getCtx(ctx, tr, "https://example.com/") }()
	<-d.started
	cancel()
	<-done
	close(d.gate)
	srv.NextConn(t) // the late dial completed its handshake
	if err := getCtx(context.Background(), tr, "https://example.com/"); err != nil {
		t.Fatal(err)
	}
	if n := d.dials.Load(); n != 1 {
		t.Fatalf("%d dials, want 1: the late connection was not pooled", n)
	}
}

// R2: a late http/1.1 connection that no request takes is closed, without
// any request written on it.
func TestFirstConnLateHTTP1Closed(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	d := newGatedDialer(srv.Addr)
	tr := d.transport(srv.RootCAs)
	defer tr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- getCtx(ctx, tr, "https://example.com/") }()
	<-d.started
	cancel()
	<-done
	close(d.gate)
	c := srv.NextConn(t)
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("unused http/1.1 connection left open")
	}
	if b := c.Bytes(); len(b) != 0 {
		t.Fatalf("unused connection carried %q", b)
	}
}

// R2: an origin learned as http/1.1 dials in parallel; when those dials
// negotiate h2, one connection enters the pool and the extra ones are
// closed.
func TestFirstConnExtraH2Closed(t *testing.T) {
	const n = 3
	h1 := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	h2srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	roots := x509.NewCertPool()
	roots.AddCert(h1.Certificate)
	roots.AddCert(h2srv.Certificate)
	var dials atomic.Int32
	var arrived sync.WaitGroup
	arrived.Add(n)
	tr := &dispatch.Transport{
		Spec: chromeSpec,
		TLS:  &utls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			addr := h1.Addr
			if dials.Add(1) > 1 {
				addr = h2srv.Addr
				// Hold every parallel dial until all of them started.
				arrived.Done()
				arrived.Wait()
			}
			var nd net.Dialer
			return nd.DialContext(ctx, network, addr)
		},
	}
	defer tr.Close()
	if err := getCtx(context.Background(), tr, "https://example.com/"); err != nil {
		t.Fatal(err)
	}
	// The origin stays learned as http/1.1; without its idle connection,
	// each request dials.
	tr.CloseIdleConnections()

	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if err := getCtx(context.Background(), tr, "https://example.com/"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if c := h2srv.Accepted(); c != n {
		t.Fatalf("%d h2 connections, want %d", c, n)
	}
	closed, open := 0, 0
	for range n {
		select {
		case <-h2srv.NextConn(t).Done():
			closed++
		case <-time.After(500 * time.Millisecond):
			open++
		}
	}
	if closed != n-1 || open != 1 {
		t.Fatalf("%d closed, %d open; want %d closed and the pooled one open", closed, open, n-1)
	}
}

// With SETTINGS_MAX_CONCURRENT_STREAMS = 1, requests queue on the session
// instead of opening more connections to the origin.
func TestFirstConnStrictMaxConcurrentStreams(t *testing.T) {
	srv := lab.Start(t, lab.Options{
		NextProtos: []string{"h2"},
		H2:         func(s *http2.Server) { s.MaxConcurrentStreams = 1 },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(20 * time.Millisecond)
			io.WriteString(w, "ok")
		}),
	})
	tr := transport(srv)
	defer tr.Close()
	fetch(t, tr, "https://example.com/warm") // SETTINGS received
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() { fetch(t, tr, "https://example.com/") })
	}
	wg.Wait()
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
}

// tls-client cached_transports_race_test: a server that negotiates a
// different protocol on every handshake, under concurrent requests and idle
// closes. Every request reaches the engine of its connection's protocol,
// and the race detector sees the learned-protocol cache from both sides.
func TestFirstConnALPNAlternatingRace(t *testing.T) {
	h1 := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	h2srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	roots := x509.NewCertPool()
	roots.AddCert(h1.Certificate)
	roots.AddCert(h2srv.Certificate)
	var dials atomic.Int32
	tr := &dispatch.Transport{
		Spec: chromeSpec,
		TLS:  &utls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			addr := h1.Addr
			if dials.Add(1)%2 == 0 {
				addr = h2srv.Addr
			}
			var nd net.Dialer
			return nd.DialContext(ctx, network, addr)
		},
	}
	defer tr.Close()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				if err := getCtx(context.Background(), tr, "https://example.com/"); err != nil {
					t.Error(err)
					return
				}
				tr.CloseIdleConnections()
			}
		})
	}
	wg.Wait()
}

// The shared dial belongs to the Transport: Close cancels it, so a request
// without a deadline waiting for it ends with ErrClosed instead of waiting
// for the dial timeout.
func TestFirstConnCloseCancelsSharedDial(t *testing.T) {
	srv := lab.Start(t, lab.Options{})
	d := newGatedDialer(srv.Addr) // the gate never opens
	tr := d.transport(srv.RootCAs)
	errc := make(chan error, 1)
	go func() { errc <- getCtx(context.Background(), tr, "https://example.com/") }()
	<-d.started
	tr.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, dispatch.ErrClosed) {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request still waiting for the dial after Close")
	}
}
