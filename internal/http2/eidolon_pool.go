// Pool fed by a caller that dials and reads ALPN itself, as net/http does
// through ConfigureTransports.

package http2

import (
	"net"
	"net/http"
)

// NewPooledTransport returns a Transport whose pool never dials:
// connections enter it through AddConn.
func NewPooledTransport() *Transport {
	pool := new(clientConnPool)
	t := &Transport{ConnPool: noDialClientConnPool{pool}}
	pool.t = t
	return t
}

// AddConn hands c, which negotiated h2, to the pool under key. If the pool
// already has a connection for key that can take a new request, c is not
// used and the caller closes it. Concurrent calls for the same key are
// coalesced. t must come from NewPooledTransport.
func (t *Transport) AddConn(key string, c net.Conn) (used bool, err error) {
	return t.connPool().(noDialClientConnPool).addConnIfNeeded(key, t, c)
}

// RoundTripPooled sends req once on a pooled connection for key. When no
// pooled connection can take the request, it returns ErrNoCachedConn and
// req, to send on a new connection. On another failure it returns the
// request to send again when the engine knows the server did not process
// it (REFUSED_STREAM, a stream above the last one of a graceful GOAWAY),
// with a fresh body if needed, or nil. A connection that closed before
// its first stream is reported as ErrNoCachedConn. It never retries by
// itself: the caller keeps the budget.
func (t *Transport) RoundTripPooled(req *http.Request, key string) (*http.Response, *http.Request, error) {
	next := req
	res, err := t.roundTripOpt(req, RoundTripOpt{key: key, next: &next})
	if err == errClientConnNotEstablished {
		// The connection closed before its first stream, so nothing was
		// sent: as when no pooled connection can take the request, the
		// caller dials again within its budget.
		return nil, req, ErrNoCachedConn
	}
	return res, next, err
}
