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

// RoundTripPooled sends req on a pooled connection for key, retrying on
// another pooled connection when the engine judges it safe. When no pooled
// connection can take the request, it returns ErrNoCachedConn and the
// request to send on a new connection: req itself, or a copy with a fresh
// body after a failure the engine can retry.
func (t *Transport) RoundTripPooled(req *http.Request, key string) (*http.Response, *http.Request, error) {
	next := req
	res, err := t.roundTripOpt(req, RoundTripOpt{key: key, next: &next})
	return res, next, err
}
