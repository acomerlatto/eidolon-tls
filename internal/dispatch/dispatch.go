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
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/order"
	"github.com/acomerlatto/eidolon-tls/internal/target"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// Transport is an http.RoundTripper that pools HTTP/2 and HTTP/1.1
// connections per origin and endpoint.
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
	// IdleConnTimeout bounds how long an HTTP/1.1 connection stays idle
	// in the pool. Zero means DefaultIdleConnTimeout. HTTP/2 connections
	// have no idle timeout, as in Chrome.
	IdleConnTimeout time.Duration
	// Order is the header order of the client, below the order of the
	// request (the keys of Header, then the context) in precedence
	// (order.Merge). Nil leaves the request's.
	Order *order.Order
	// MaxResponseHeaderBytes bounds the headers of a response: over
	// HTTP/1.1 the bytes read with them, 1xx included; over HTTP/2 the
	// header list, as announced in SETTINGS_MAX_HEADER_LIST_SIZE. Zero
	// means http1.DefaultMaxHeaderBytes (256 KiB, as Chrome).
	MaxResponseHeaderBytes int64
	// DisableDecompression delivers gzip and deflate bodies as they came,
	// with Content-Encoding. By default they are decoded (decompress).
	DisableDecompression bool
	// Protocols restricts the protocols offered by ALPN, and accepted
	// from it, to tlsdial.ProtoHTTP1 and tlsdial.ProtoH2 as listed. Nil
	// keeps the spec as it is and accepts both.
	Protocols []string

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
	// h1Required marks the keys whose server answered HTTP_1_1_REQUIRED:
	// their new connections offer only http/1.1, as Chrome does.
	h1Required map[string]bool
	// dialCtx is the context of the shared dials, canceled by Close.
	dialCtx     context.Context
	cancelDials context.CancelFunc
}

// ErrClosed reports a request on a closed Transport.
var ErrClosed = errors.New("eidolon: transport closed")

// ErrExactHeadersRedirect reports a redirect of a request in exact mode.
// http.Client filters credentials out of Header on redirects, but the
// exact fields travel in the context and would escape that filter.
var ErrExactHeadersRedirect = errors.New("eidolon: redirect of a request with exact headers")

// ErrProtocolPolicy reports a protocol outside the enabled set: negotiated
// by the server, required by it, or needed by the URL.
var ErrProtocolPolicy = errors.New("eidolon: protocol outside the enabled set")

// ErrRetryBudget reports a request that could have been sent again but
// was not, because its budget ran out: maxRetries retries, maxDials
// replays or dials. It wraps the last error.
var ErrRetryBudget = errors.New("eidolon: retry budget exhausted")

// overBudget reports err as the last error of a request out of budget.
func overBudget(err error) error {
	return fmt.Errorf("%w: %w", ErrRetryBudget, err)
}

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
	if req.Response != nil && order.ExactFromContext(req.Context()) != nil {
		closeBody(req)
		return nil, ErrExactHeadersRedirect
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
	// The order keys of Header are never sent; the order travels to the
	// engines in the context.
	merged := order.Merge(order.FromHeader(req.Header), order.FromContext(req.Context()), t.Order)
	if merged != nil {
		sent = *sent.WithContext(order.WithOrder(req.Context(), *merged))
	}
	sent.Header = redirectHeader(req, order.WithoutKeys(req.Header))
	if q := target.EncodeQuery(req.URL.RawQuery); q != req.URL.RawQuery {
		u := *req.URL
		u.RawQuery = q
		sent.URL = &u
	}
	resp, err := t.roundTrip(&sent, tgt)
	var se http2.StreamError
	if errors.As(err, &se) && se.Cause == http2.ErrHeaderListSize ||
		errors.Is(err, http2.ErrHeaderListSize) {
		// One error for the limit of both engines.
		err = fmt.Errorf("%w: %w", http1.ErrHeaderTooLarge, err)
	}
	if err != nil && t.isClosed() && !errors.Is(err, ErrClosed) {
		// Keep the cause, such as context.Canceled.
		err = fmt.Errorf("%w: %w", ErrClosed, err)
	}
	if err != nil {
		return nil, err
	}
	resp.Request = req
	if !t.DisableDecompression {
		decompress(resp)
	}
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
		if !t.allows(tlsdial.ProtoHTTP1) {
			closeBody(req)
			return nil, fmt.Errorf("%w: http:// needs HTTP/1.1", ErrProtocolPolicy)
		}
		dial := func(ctx context.Context) (net.Conn, *tls.ConnectionState, error) {
			conn, err := t.dial(ctx, tgt.Addr())
			return conn, nil, err
		}
		fresh := false
		for replays := 0; ; replays++ {
			c, err := t.h1Get(ctx, key, fresh, dial)
			if err != nil {
				closeBody(req)
				return nil, err
			}
			resp, again, err := t.sendH1(c, req)
			if again == nil {
				return resp, err
			}
			if replays == maxDials {
				closeBody(again)
				return nil, overBudget(err)
			}
			req, fresh = again, true
		}
	}

	h2 := t.h2t()

	// The engine reports through GotConn which connection each attempt
	// used; the hook runs on this goroutine.
	var got httptrace.GotConnInfo
	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(ci httptrace.GotConnInfo) { got = ci },
	}))

	// fresh: after a lost HTTP/1.1 connection, the replay goes to a new
	// one (h1Acquire). A lost HTTP/2 connection leaves the pool by itself.
	fresh := false
	for dials, retries, replays := 0, 0, 0; ; {
		got = httptrace.GotConnInfo{}
		watched, body := watchBody(req)
		var resp *http.Response
		next, err := watched, error(http2.ErrNoCachedConn)
		if !t.h1Only(key) {
			resp, next, err = h2.RoundTripPooled(watched, key)
		}
		if err == nil {
			return resp, nil
		}
		if http11Required(err) {
			// RFC 9113 section 7: the server wants HTTP/1.1. Chrome
			// remembers it for the origin and sends the request again
			// over HTTP/1.1, whatever the method: it was refused.
			if !t.allows(tlsdial.ProtoHTTP1) {
				return nil, fmt.Errorf("%w: the server requires HTTP/1.1: %w", ErrProtocolPolicy, err)
			}
			t.requireH1(key)
			if body.failed() || ctx.Err() != nil || t.isClosed() {
				return nil, err
			}
			r, ok := rewindBody(req)
			if !ok {
				return nil, err
			}
			if replays == maxDials {
				closeBody(r)
				return nil, overBudget(err)
			}
			replays++
			req = r
			continue
		}
		if !errors.Is(err, http2.ErrNoCachedConn) && next != nil {
			// The engine knows the server did not process the request:
			// REFUSED_STREAM, or a stream above the last one of a
			// graceful GOAWAY. Chrome sends it again, whatever the
			// method, at once and at most twice.
			if body.failed() || ctx.Err() != nil || t.isClosed() {
				return nil, err
			}
			if retries == maxRetries {
				closeBody(next)
				return nil, overBudget(err)
			}
			retries++
			req = next
			continue
		}
		if !errors.Is(err, http2.ErrNoCachedConn) {
			// Section 6.3: a request is sent again on a new connection
			// only if the reused idle connection was lost and the
			// request can be replayed. WasIdle implies Reused. An error
			// of the request body is not a lost connection, whatever it
			// looks like.
			if !got.WasIdle || !connLost(err) || body.failed() || ctx.Err() != nil || t.isClosed() {
				return nil, err
			}
			r, ok := rewind(req)
			if !ok {
				return nil, err
			}
			if replays == maxDials {
				closeBody(r)
				return nil, overBudget(err)
			}
			replays++
			req = r
			continue
		}
		req = next // watched
		if dials == maxDials {
			closeBody(req)
			return nil, fmt.Errorf("%w: no usable connection to %s after %d dials", ErrRetryBudget, tgt.Origin(), dials)
		}

		dials++
		c, err := t.connFor(ctx, tgt, key, fresh)
		if err != nil {
			closeBody(req)
			return nil, err
		}
		if c == nil {
			continue // an h2 connection was pooled
		}
		resp, again, err := t.sendH1(c, req)
		if again == nil {
			return resp, err
		}
		if replays == maxDials {
			closeBody(again)
			return nil, overBudget(err)
		}
		replays++
		req, fresh = again, true
	}
}

// maxDials bounds the new connections one request opens when each one
// is lost before taking it, such as a server that closes right after the
// handshake. It also bounds the replays after lost idle connections.
const maxDials = 3

// maxRetries bounds the retries of a request the server did not process,
// as Chrome's kMaxRetryAttempts.
const maxRetries = 2

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

// dialTimeout bounds a TLS dial, TCP and handshake, as Chrome bounds the
// handshake (kSSLHandshakeTimeout, 30 s): a server that accepts and never
// answers does not hold a request without deadline, nor its slot. A
// variable for the tests.
var dialTimeout = 30 * time.Second

// dialTLS opens a TLS connection to tgt and records its protocol for key.
// It stops at ctx or after dialTimeout.
func (t *Transport) dialTLS(ctx context.Context, tgt target.Target, key string) (*utls.UConn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	cfg := t.TLS
	if cfg == nil {
		cfg = &utls.Config{}
	}
	cfg = cfg.Clone()
	cfg.ServerName = tgt.ServerName()
	t.mu.Lock()
	protos := t.offerLocked(key)
	t.mu.Unlock()
	conn, err := tlsdial.Dial(ctx, "tcp", tgt.Addr(), tlsdial.Config{
		Spec:        t.spec(protos),
		TLS:         cfg,
		DialContext: t.trackedDial,
	})
	if err != nil {
		return nil, err
	}
	proto := conn.ConnectionState().NegotiatedProtocol
	if proto == "" {
		proto = tlsdial.ProtoHTTP1 // no ALPN is served by HTTP/1.1
	}
	if protos != nil && !slices.Contains(protos, proto) {
		conn.Close()
		return nil, fmt.Errorf("%w: the server negotiated %s", ErrProtocolPolicy, proto)
	}
	t.learn(key, proto)
	return conn, nil
}

// spec returns the spec function of a connection that offers protos, or
// the spec as it is for nil.
func (t *Transport) spec(protos []string) func() (*utls.ClientHelloSpec, error) {
	if protos == nil {
		return t.Spec
	}
	return func() (*utls.ClientHelloSpec, error) {
		s, err := t.Spec()
		if err != nil || s == nil {
			return s, err
		}
		if err := tlsdial.RestrictALPN(s, protos); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrProtocolPolicy, err)
		}
		return s, nil
	}
}

// CheckSpec builds and applies one spec, restricted to Protocols, as a
// dial does, without connecting. Its errors wrap tlsdial.ErrProfile.
func (t *Transport) CheckSpec() error {
	return tlsdial.Check(tlsdial.Config{Spec: t.spec(t.Protocols), TLS: t.TLS})
}

// offerLocked returns the protocols a new connection of key offers, or nil
// for the spec as it is.
func (t *Transport) offerLocked(key string) []string {
	if t.h1Required[key] && t.allows(tlsdial.ProtoHTTP1) {
		return []string{tlsdial.ProtoHTTP1}
	}
	return t.Protocols
}

// allows reports whether proto is enabled.
func (t *Transport) allows(proto string) bool {
	return t.Protocols == nil || slices.Contains(t.Protocols, proto)
}

// h1Only reports whether requests of key skip the HTTP/2 pool.
func (t *Transport) h1Only(key string) bool {
	if !t.allows(tlsdial.ProtoH2) {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.h1Required[key]
}

// requireH1 records that the server of key requires HTTP/1.1.
func (t *Transport) requireH1(key string) {
	t.mu.Lock()
	if t.h1Required == nil {
		t.h1Required = make(map[string]bool)
	}
	t.h1Required[key] = true
	if t.protos == nil {
		t.protos = make(map[string]string)
	}
	t.protos[key] = tlsdial.ProtoHTTP1
	t.mu.Unlock()
}

// http11Required reports an HTTP_1_1_REQUIRED from the server, in
// RST_STREAM or GOAWAY.
func http11Required(err error) bool {
	var se http2.StreamError
	if errors.As(err, &se) && se.Code == http2.ErrCodeHTTP11Required {
		return true
	}
	var ge http2.GoAwayError
	return errors.As(err, &ge) && ge.ErrCode == http2.ErrCodeHTTP11Required
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
		// The limit is also what SETTINGS announces.
		t.h2.MaxHeaderListSize = uint32(t.maxHeaderBytes())
	})
	return t.h2
}

// maxHeaderBytes returns the response header limit of both engines.
func (t *Transport) maxHeaderBytes() int64 {
	if t.MaxResponseHeaderBytes > 0 {
		return t.MaxResponseHeaderBytes
	}
	return http1.DefaultMaxHeaderBytes
}

// newHTTP1 returns an HTTP/1.1 connection over c with the header limit.
func (t *Transport) newHTTP1(c net.Conn) *http1.Conn {
	hc := http1.NewConn(c)
	hc.MaxHeaderBytes = t.maxHeaderBytes()
	return hc
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}
