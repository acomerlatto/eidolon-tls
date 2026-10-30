package eidolon

import (
	"errors"
	"fmt"
	"slices"

	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// Protocol is an HTTP version the client may use.
type Protocol int

const (
	HTTP1 Protocol = iota + 1
	HTTP2
	// HTTP3 is accepted and has no effect yet: the client never uses QUIC,
	// and an Alt-Svc header that announces h3 changes nothing.
	HTTP3
)

func (p Protocol) String() string {
	switch p {
	case HTTP1:
		return "HTTP/1.1"
	case HTTP2:
		return "HTTP/2"
	case HTTP3:
		return "HTTP/3"
	}
	return fmt.Sprintf("Protocol(%d)", int(p))
}

// WithProtocols enables only the listed protocols. By default every
// protocol of the ClientHello spec is enabled. A server that negotiates,
// or requires, another one fails the request with ErrProtocolPolicy.
//
// Leaving HTTP/1.1 or HTTP/2 out changes the ClientHello: ALPN offers only
// the enabled protocols, and ALPS only those ALPN still offers. The
// fingerprint is then no longer the one of the spec. It cannot be combined
// with WithForceHTTP1 or WithForceHTTP2. The list is copied when
// WithProtocols is called. The queries of WithDoH follow it too.
func WithProtocols(ps ...Protocol) Option {
	// Copied now: ps may be the caller's slice.
	ps = slices.Clone(ps)
	return func(c *config) error {
		if len(ps) == 0 {
			return errors.New("WithProtocols: no protocol")
		}
		for _, p := range ps {
			if p < HTTP1 || p > HTTP3 {
				return fmt.Errorf("WithProtocols: unknown %v", p)
			}
		}
		c.protocols = ps
		return nil
	}
}

// WithForceHTTP1 enables only HTTP/1.1, as WithProtocols(HTTP1).
func WithForceHTTP1() Option {
	return func(c *config) error { c.force |= 1 << HTTP1; return nil }
}

// WithForceHTTP2 enables only HTTP/2, as WithProtocols(HTTP2). URLs with
// the http scheme then fail: there is no HTTP/2 over cleartext.
func WithForceHTTP2() Option {
	return func(c *config) error { c.force |= 1 << HTTP2; return nil }
}

// WithDisableHTTP3 leaves HTTP/3 out. It changes nothing yet: the client
// never uses QUIC.
func WithDisableHTTP3() Option {
	return func(c *config) error { c.disableHTTP3 = true; return nil }
}

// alpn resolves the protocol options into the ALPN protocols the
// dispatcher restricts to, nil for no restriction.
func (c *config) alpn() ([]string, error) {
	switch {
	case c.force == 1<<HTTP1|1<<HTTP2:
		return nil, errors.New("WithForceHTTP1 and WithForceHTTP2 together")
	case c.force != 0 && c.protocols != nil:
		return nil, errors.New("WithProtocols together with WithForceHTTP1 or WithForceHTTP2")
	}
	enabled := []Protocol{HTTP1, HTTP2, HTTP3}
	switch {
	case c.protocols != nil:
		enabled = c.protocols
	case c.force == 1<<HTTP1:
		enabled = []Protocol{HTTP1}
	case c.force == 1<<HTTP2:
		enabled = []Protocol{HTTP2}
	}
	h1, h2 := slices.Contains(enabled, HTTP1), slices.Contains(enabled, HTTP2)
	switch {
	case h1 && h2:
		return nil, nil
	case h1:
		return []string{tlsdial.ProtoHTTP1}, nil
	case h2:
		return []string{tlsdial.ProtoH2}, nil
	}
	if slices.Contains(enabled, HTTP3) && !c.disableHTTP3 {
		return nil, errors.New("no protocol enabled besides HTTP/3, which is not supported yet")
	}
	return nil, errors.New("no protocol enabled")
}
