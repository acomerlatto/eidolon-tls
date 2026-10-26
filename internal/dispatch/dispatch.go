// Package dispatch is the single entry point to the HTTP engines: it dials,
// reads the protocol negotiated by ALPN and hands the connection to the
// HTTP/2 or the HTTP/1.1 engine.
//
// Each request still uses its own connection, closed with the response
// body. Pools, waiters for the first connection of an origin and the
// protocol policy come in later M1 steps.
package dispatch

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/target"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// Transport is an http.RoundTripper that sends each request on a new
// connection.
type Transport struct {
	// Spec returns a new ClientHello spec per connection.
	Spec func() (*utls.ClientHelloSpec, error)
	// TLS holds the verification settings; ServerName is set per request.
	// Nil uses the system roots.
	TLS *utls.Config
	// DialContext opens TCP connections. Nil uses a zero net.Dialer.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Spelling is the HTTP/1.1 name spelling table.
	Spelling http1.Spelling

	h2once sync.Once
	h2     *http2.Transport

	mu     sync.Mutex
	closed bool
	conns  map[*trackedConn]struct{}
}

// ErrClosed reports a request on a closed Transport.
var ErrClosed = errors.New("eidolon: transport closed")

// RoundTrip implements http.RoundTripper.
//
// The destination is normalized by internal/target: the URL decides the
// endpoint and the verification name; Host (HTTP/1.1) and :authority
// (HTTP/2) use the normalized authority unless req.Host overrides it, as in
// net/http. The caller's request is not modified.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.isClosed() {
		closeBody(req)
		return nil, ErrClosed
	}
	tgt, err := target.Parse(req.URL)
	if err != nil {
		closeBody(req)
		return nil, err
	}
	sent := req
	if req.Host == "" {
		r := *req
		r.Host = tgt.Authority()
		sent = &r
	}
	resp, err := t.roundTrip(sent, tgt)
	if err != nil && t.isClosed() {
		return nil, ErrClosed
	}
	if resp != nil {
		resp.Request = req
	}
	return resp, err
}

// CloseIdleConnections closes idle connections. Without a pool there are
// none yet: every connection belongs to a request in progress.
func (t *Transport) CloseIdleConnections() {}

// Close stops the transport: new requests fail with ErrClosed and every
// open connection is closed, including responses still being read.
func (t *Transport) Close() error {
	t.mu.Lock()
	t.closed = true
	conns := t.conns
	t.conns = nil
	t.mu.Unlock()
	for c := range conns {
		c.Conn.Close()
	}
	return nil
}

func (t *Transport) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *Transport) roundTrip(req *http.Request, tgt target.Target) (*http.Response, error) {
	ctx := req.Context()
	if tgt.Scheme == "http" {
		conn, err := t.dial(ctx, tgt.Addr())
		if err != nil {
			closeBody(req)
			return nil, err
		}
		return t.roundTripHTTP1(conn, req, nil)
	}

	cfg := t.TLS
	if cfg == nil {
		cfg = &utls.Config{}
	}
	cfg = cfg.Clone()
	cfg.ServerName = tgt.ServerName()
	conn, err := tlsdial.Dial(ctx, "tcp", tgt.Addr(), tlsdial.Config{
		Spec:        t.Spec,
		TLS:         cfg,
		DialContext: t.trackedDial,
	})
	if err != nil {
		closeBody(req)
		return nil, err
	}
	std := tlsdial.StdConn{UConn: conn}
	if conn.ConnectionState().NegotiatedProtocol == tlsdial.ProtoH2 {
		return t.roundTripH2(std, req)
	}
	state := std.ConnectionState()
	return t.roundTripHTTP1(std, req, &state)
}

func (t *Transport) dial(ctx context.Context, addr string) (net.Conn, error) {
	return t.trackedDial(ctx, "tcp", addr)
}

// trackedDial opens a TCP connection and registers it until it is closed,
// so Close can reach it. A dial that ends after Close closes its connection.
func (t *Transport) trackedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	dial := t.DialContext
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	conn, err := dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: conn, t: t}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		conn.Close()
		return nil, ErrClosed
	}
	if t.conns == nil {
		t.conns = make(map[*trackedConn]struct{})
	}
	t.conns[tc] = struct{}{}
	t.mu.Unlock()
	return tc, nil
}

// trackedConn leaves the transport's set when it is closed.
type trackedConn struct {
	net.Conn
	t    *Transport
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.t.mu.Lock()
		delete(c.t.conns, c)
		c.t.mu.Unlock()
	})
	return c.Conn.Close()
}

func (t *Transport) roundTripH2(conn net.Conn, req *http.Request) (*http.Response, error) {
	t.h2once.Do(func() { t.h2 = &http2.Transport{} })
	cc, err := t.h2.NewClientConn(conn)
	if err != nil {
		conn.Close()
		closeBody(req)
		return nil, err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		cc.Close()
		return nil, err
	}
	resp.Body = &connBody{ReadCloser: resp.Body, conn: cc}
	return resp, nil
}

func (t *Transport) roundTripHTTP1(conn net.Conn, req *http.Request, state *tls.ConnectionState) (*http.Response, error) {
	stop := context.AfterFunc(req.Context(), func() { conn.Close() })
	resp, err := http1.RoundTrip(conn, req, t.Spelling)
	closeBody(req)
	if err != nil {
		stop()
		conn.Close()
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	resp.TLS = state
	resp.Body = &connBody{ReadCloser: resp.Body, conn: conn, stop: stop}
	return resp, nil
}

// connBody closes the connection with the response body.
type connBody struct {
	io.ReadCloser
	conn interface{ Close() error }
	stop func() bool
	once sync.Once
}

// Close closes the connection before the body: an HTTP/1.1 body from
// http.ReadResponse reads to the end on Close, which never returns for a
// body the server does not finish. Without a pool the connection is
// discarded anyway (section 6.3: no unbounded drain).
func (b *connBody) Close() error {
	b.once.Do(func() {
		if b.stop != nil {
			b.stop()
		}
		b.conn.Close()
	})
	b.ReadCloser.Close()
	return nil
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}
