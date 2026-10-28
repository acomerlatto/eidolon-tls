package eidolon

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
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
	jar         http.CookieJar

	disableDecompression bool

	maxConnsPerHost int
	idleConnTimeout time.Duration

	order    *order.Order
	spelling http1.Spelling
	h2       *dispatch.H2Preface

	profile *profile // WithProfile, applied by New under the options above

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
// certificates. The pool is copied when WithRootCAs is called. Without it,
// the system roots are used.
func WithRootCAs(pool *x509.CertPool) Option {
	// Cloned now: the pool is the caller's.
	var clone *x509.CertPool
	if pool != nil {
		clone = pool.Clone()
	}
	return func(c *config) error {
		if clone == nil {
			return errors.New("WithRootCAs: nil pool")
		}
		c.rootCAs = clone
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

// WithMaxConnsPerHost bounds the HTTP/1.1 connections per origin; requests
// over the limit wait for a connection, each until its own context ends.
// The default is 6, as Chrome. HTTP/2 uses one connection per origin.
func WithMaxConnsPerHost(n int) Option {
	return func(c *config) error {
		if n <= 0 {
			return fmt.Errorf("WithMaxConnsPerHost: %d is not positive", n)
		}
		c.maxConnsPerHost = n
		return nil
	}
}

// WithIdleConnTimeout bounds how long an idle HTTP/1.1 connection is kept
// for reuse. The default is 300 seconds, as Chrome for a connection that
// served a request. HTTP/2 connections are kept until the server or
// CloseIdleConnections closes them, as Chrome does.
func WithIdleConnTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return errors.New("WithIdleConnTimeout: duration not positive")
		}
		c.idleConnTimeout = d
		return nil
	}
}

// WithCookieJar sets the cookie jar of the client's own methods, as
// http.Client.Jar does: cookies from Set-Cookie, including redirect
// responses, are stored, and those of each URL are added to its Cookie
// field. Without it there is no jar. NewCookieJar returns one with the
// public suffix list. It is not part of Transport(): the http.Client that
// uses it sets its own jar. In exact mode (WithExactHeaders) no cookie of
// the jar is sent.
func WithCookieJar(jar http.CookieJar) Option {
	return func(c *config) error {
		if jar == nil {
			return errors.New("WithCookieJar: nil jar")
		}
		c.jar = jar
		return nil
	}
}

// WithDisableDecompression delivers response bodies as the server sent
// them. By default a body with Content-Encoding gzip, deflate, br or zstd
// (windows up to 8 MiB, as Chrome) is decoded, as browsers do: the response
// loses Content-Encoding and Content-Length, and Response.Uncompressed is
// set. Other codings, and several codings, are always delivered as they
// came. Accept-Encoding is never added: it comes from the request or the
// profile.
func WithDisableDecompression() Option {
	return func(c *config) error {
		c.disableDecompression = true
		return nil
	}
}

// WithDefaultOrder sets the header order of the client's requests. The
// order of a request (HeaderOrderKey, PHeaderOrderKey) takes precedence;
// see Order. The lists are copied when WithDefaultOrder is called.
func WithDefaultOrder(o Order) Option {
	// Copied now: the slices of o are the caller's. The Order is new on
	// each use, since a profile may fill its Pseudo.
	pseudo, header := slices.Clone(o.Pseudo), slices.Clone(o.Header)
	return func(c *config) error {
		c.order = &order.Order{Pseudo: pseudo, Header: header}
		return nil
	}
}

// WithHeaderSpelling sets how header names are spelled over HTTP/1.1, such
// as "sec-ch-ua" in lowercase next to "User-Agent". http.Header
// canonicalizes its keys, so the spelling of a name comes from here; names
// not listed are sent in canonical form. Over HTTP/2 names are always
// lowercase. The names are copied when WithHeaderSpelling is called.
func WithHeaderSpelling(names ...string) Option {
	// Validated now: names may be the caller's slice.
	sp, err := spelling(names)
	return func(c *config) error {
		if err != nil {
			return fmt.Errorf("WithHeaderSpelling: %w", err)
		}
		c.spelling = sp
		return nil
	}
}

// spelling validates names and returns their spelling table.
func spelling(names []string) (http1.Spelling, error) {
	sp := make(http1.Spelling, len(names))
	for _, n := range names {
		if !httpguts.ValidHeaderFieldName(n) {
			return nil, fmt.Errorf("invalid name %q", n)
		}
		key := strings.ToLower(n)
		if prev, ok := sp[key]; ok && prev != n {
			return nil, fmt.Errorf("%q and %q spell one name", prev, n)
		}
		sp[key] = n
	}
	return sp, nil
}
