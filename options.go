package eidolon

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// Option configures a client in New. Options fill a private configuration
// that New validates; the client cannot be changed afterwards.
type Option func(*config) error

type config struct {
	clientHello func() (*utls.ClientHelloSpec, error)
	rootCAs     *x509.CertPool
	timeout     time.Duration
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	order    *order.Order
	spelling http1.Spelling

	protocols    []Protocol // WithProtocols; nil if not used
	force        int        // bits 1<<HTTP1 and 1<<HTTP2 of WithForceHTTP*
	disableHTTP3 bool
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
// http.Client.Timeout does. Zero means no limit. It applies to the client's
// own methods, not to an http.Client built on Transport().
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

// WithDefaultOrder sets the header order of the client's requests. The
// order of a request (HeaderOrderKey, PHeaderOrderKey) takes precedence;
// see Order. The lists are copied.
func WithDefaultOrder(o Order) Option {
	return func(c *config) error {
		c.order = &order.Order{Pseudo: slices.Clone(o.Pseudo), Header: slices.Clone(o.Header)}
		return nil
	}
}

// WithHeaderSpelling sets how header names are spelled over HTTP/1.1, such
// as "sec-ch-ua" in lowercase next to "User-Agent". http.Header
// canonicalizes its keys, so the spelling of a name comes from here; names
// not listed are sent in canonical form. Over HTTP/2 names are always
// lowercase.
func WithHeaderSpelling(names ...string) Option {
	return func(c *config) error {
		sp := make(http1.Spelling, len(names))
		for _, n := range names {
			if !httpguts.ValidHeaderFieldName(n) {
				return fmt.Errorf("WithHeaderSpelling: invalid name %q", n)
			}
			key := strings.ToLower(n)
			if prev, ok := sp[key]; ok && prev != n {
				return fmt.Errorf("WithHeaderSpelling: %q and %q spell one name", prev, n)
			}
			sp[key] = n
		}
		c.spelling = sp
		return nil
	}
}
