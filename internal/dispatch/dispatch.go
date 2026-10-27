// Package dispatch is the single entry point to the HTTP engines: it dials,
// reads the protocol negotiated by ALPN and hands the connection to the
// HTTP/2 or the HTTP/1.1 engine.
//
// HTTP/2 connections stay in the engine's own pool, keyed by origin and
// endpoint; the profile, TLS settings and trust are fixed per Transport, so
// each Transport has its own pool. An HTTP/1.1 request still uses its own
// connection, closed with the response body. While no connection of an
// origin is usable, its requests wait for one shared dial (firstconn.go).
// The HTTP/1.1 pool and the protocol policy come in later M1 steps.
package dispatch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/target"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// Transport is an http.RoundTripper that reuses HTTP/2 connections and
// sends each HTTP/1.1 request on a new connection.
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
	// MaxConnsPerHost bounds the HTTP/1.1 connections per origin and
	// endpoint. Zero means DefaultMaxConnsPerHost.
	MaxConnsPerHost int

	h2once sync.Once
	h2     *http2.Transport

	mu     sync.Mutex
	closed bool
	conns  map[*trackedConn]struct{}
	// protos holds the protocol learned per key; dialing, the shared
	// dial in progress per key.
	protos  map[string]string
	dialing map[string]*dialCall
	// h1 holds the HTTP/1.1 pool per key.
	h1 map[string]*h1Host
	// dialCtx is the context of the shared dials, canceled by Close.
	dialCtx     context.Context
	cancelDials context.CancelFunc
}

// ErrClosed reports a request on a closed Transport.
var ErrClosed = errors.New("eidolon: transport closed")

// RoundTrip implements http.RoundTripper.
//
// The destination is normalized by internal/target: the URL decides the
// endpoint and the verification name; Host (HTTP/1.1) and :authority
// (HTTP/2) use the normalized authority unless req.Host overrides it, as in
// net/http, and the override is normalized the same way. The query is
// percent-encoded as Chrome sends it. The caller's request is not modified.
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
	sent := *req
	sent.Host = tgt.Authority()
	if req.Host != "" {
		h, err := target.Parse(&url.URL{Scheme: tgt.Scheme, Host: req.Host})
		if err != nil {
			closeBody(req)
			return nil, fmt.Errorf("eidolon: invalid Host %q: %w", req.Host, err)
		}
		sent.Host = h.Authority()
	}
	if q := target.EncodeQuery(req.URL.RawQuery); q != req.URL.RawQuery {
		u := *req.URL
		u.RawQuery = q
		sent.URL = &u
	}
	resp, err := t.roundTrip(&sent, tgt)
	if err != nil && t.isClosed() && !errors.Is(err, ErrClosed) {
		// Keep the cause, such as context.Canceled.
		err = fmt.Errorf("%w: %w", ErrClosed, err)
	}
	if err != nil {
		return nil, err
	}
	resp.Request = req
	return resp, nil
}

// CloseIdleConnections closes the pooled connections that carry no
// request. It never interrupts a response in progress.
func (t *Transport) CloseIdleConnections() {
	t.h2t().CloseIdleConnections()
	t.closeIdleH1()
}

// Close stops the transport: new requests fail with ErrClosed and every
// open connection is closed, including responses still being read.
func (t *Transport) Close() error {
	t.mu.Lock()
	t.closed = true
	conns := t.conns
	t.conns = nil
	if t.cancelDials != nil {
		t.cancelDials()
	}
	t.stopH1Locked()
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
	// The key holds what can differ between requests of one Transport:
	// the origin and the endpoint dialed.
	key := tgt.Origin() + " " + tgt.Addr()
	if tgt.Scheme == "http" {
		dial := func(ctx context.Context) (net.Conn, *tls.ConnectionState, error) {
			conn, err := t.dial(ctx, tgt.Addr())
			return conn, nil, err
		}
		for replays := 0; ; replays++ {
			c, err := t.h1Get(ctx, key, dial)
			if err != nil {
				closeBody(req)
				return nil, err
			}
			resp, again, err := t.sendH1(c, req)
			if again == nil || replays == maxDials {
				return resp, err
			}
			req = again
		}
	}

	h2 := t.h2t()

	// The engine reports through GotConn which connection each attempt
	// used; the hook runs on this goroutine.
	var got httptrace.GotConnInfo
	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(ci httptrace.GotConnInfo) { got = ci },
	}))

	for dials, replays := 0, 0; ; {
		got = httptrace.GotConnInfo{}
		watched, body := watchBody(req)
		resp, next, err := h2.RoundTripPooled(watched, key)
		if err == nil {
			return resp, nil
		}
		if !errors.Is(err, http2.ErrNoCachedConn) {
			// Section 6.3: a request is sent again on a new connection
			// only if the reused idle connection was lost and the
			// request can be replayed. WasIdle implies Reused. An error
			// of the request body is not a lost connection, whatever it
			// looks like.
			if replays == maxDials || !got.WasIdle || !connLost(err) || body.failed() ||
				ctx.Err() != nil || t.isClosed() {
				return nil, err
			}
			r, ok := rewind(req)
			if !ok {
				return nil, err
			}
			replays++
			req = r
			continue
		}
		req = next // watched, or a copy whose body GetBody rewound
		if dials == maxDials {
			closeBody(req)
			return nil, fmt.Errorf("eidolon: no usable connection to %s after %d dials", tgt.Origin(), dials)
		}

		dials++
		c, err := t.connFor(ctx, tgt, key)
		if err != nil {
			closeBody(req)
			return nil, err
		}
		if c == nil {
			continue // an h2 connection was pooled
		}
		resp, again, err := t.sendH1(c, req)
		if again == nil || replays == maxDials {
			return resp, err
		}
		replays++
		req = again
	}
}

// maxDials bounds the new connections one request opens when each one
// is lost before taking it, such as a server that closes right after the
// handshake. It also bounds the replays after lost idle connections.
const maxDials = 3

// connLost reports whether err means the connection was lost, as opposed
// to an error about the request itself.
func connLost(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

// watchedBody records an error of the request body, so a body that fails
// is not taken for a lost connection.
type watchedBody struct {
	io.ReadCloser
	err atomic.Pointer[error]
}

func (b *watchedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		b.err.Store(&err)
	}
	return n, err
}

func (b *watchedBody) failed() bool { return b != nil && b.err.Load() != nil }

// watchBody returns req with its body wrapped in a watchedBody, or req
// itself and nil if it has no body.
func watchBody(req *http.Request) (*http.Request, *watchedBody) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	r := *req
	b := &watchedBody{ReadCloser: req.Body}
	r.Body = b
	return &r, b
}

// rewind returns req ready to be sent again, as net/http decides: a safe
// method or an idempotency key, and a body that is absent or can be
// obtained again with GetBody.
func rewind(req *http.Request) (*http.Request, bool) {
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		_, key := req.Header["Idempotency-Key"]
		_, xkey := req.Header["X-Idempotency-Key"]
		if !key && !xkey {
			return nil, false
		}
	}
	return rewindBody(req)
}

// rewindBody returns req with its body obtained again, whatever the
// method: for a request that never reached the server.
func rewindBody(req *http.Request) (*http.Request, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	r := *req
	r.Body = body
	return &r, true
}

// dialTLS opens a TLS connection to tgt and records its protocol for key.
func (t *Transport) dialTLS(ctx context.Context, tgt target.Target, key string) (*utls.UConn, error) {
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
		return nil, err
	}
	t.learn(key, conn.ConnectionState().NegotiatedProtocol)
	return conn, nil
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

// h2t returns the HTTP/2 engine, whose pool never dials: the dispatcher
// dials, reads ALPN and hands h2 connections to it.
func (t *Transport) h2t() *http2.Transport {
	t.h2once.Do(func() {
		t.h2 = http2.NewPooledTransport()
		// DisableCompression: the engine neither adds accept-encoding nor
		// decompresses the response; both belong to the profile (C9).
		t.h2.DisableCompression = true
		// One connection per key (C4): a request waits for a free stream
		// instead of opening another connection.
		t.h2.StrictMaxConcurrentStreams = true
	})
	return t.h2
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}
