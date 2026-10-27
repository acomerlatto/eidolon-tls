package eidolon

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"time"

	utls "github.com/acomerlatto/utls"
)

// Option configures a client in New. Options fill a private configuration
// that New validates; the client cannot be changed afterwards.
type Option func(*config) error

type config struct {
	clientHello func() (*utls.ClientHelloSpec, error)
	rootCAs     *x509.CertPool
	timeout     time.Duration
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// WithClientHello sets the function that returns a new ClientHello spec for
// each connection. It is required: there is no default browser profile.
// The SNI extension must leave ServerName empty: the name sent and verified
// is always the host of the URL, and a spec that sets one fails the request.
func WithClientHello(spec func() (*utls.ClientHelloSpec, error)) Option {
	return func(c *config) error {
		if spec == nil {
			return errors.New("WithClientHello: nil function")
		}
		c.clientHello = spec
		return nil
	}
}

// WithRootCAs sets the certificate authorities trusted for server
// certificates. The pool is copied. Without it, the system roots are used.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(c *config) error {
		if pool == nil {
			return errors.New("WithRootCAs: nil pool")
		}
		c.rootCAs = pool.Clone()
		return nil
	}
}

// WithTimeout limits the whole request, including reading the body, as
// http.Client.Timeout does. Zero means no limit.
func WithTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d < 0 {
			return errors.New("WithTimeout: negative duration")
		}
		c.timeout = d
		return nil
	}
}

// WithDialContext sets the function that opens TCP connections. Without it,
// a zero net.Dialer is used.
func WithDialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(c *config) error {
		if dial == nil {
			return errors.New("WithDialContext: nil function")
		}
		c.dialContext = dial
		return nil
	}
}
