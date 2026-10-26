// Package dispatch is the single entry point to the HTTP engines: it dials,
// reads the protocol negotiated by ALPN and hands the connection to the
// HTTP/2 or the HTTP/1.1 engine.
//
// This is the M0 version: one connection per request, closed with the
// response body. Pools, waiters for the first connection of an origin and
// the protocol policy come in M1.
package dispatch

import (
	"context"
	"crypto/tls"
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
}

// RoundTrip implements http.RoundTripper.
//
// The destination is normalized by internal/target: the URL decides the
// endpoint and the verification name; Host (HTTP/1.1) and :authority
// (HTTP/2) use the normalized authority unless req.Host overrides it, as in
// net/http. The caller's request is not modified.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
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
	if resp != nil {
		resp.Request = req
	}
	return resp, err
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
		DialContext: t.DialContext,
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
	if t.DialContext != nil {
		return t.DialContext(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
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

func (b *connBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		if b.stop != nil {
			b.stop()
		}
		b.conn.Close()
	})
	return err
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}
