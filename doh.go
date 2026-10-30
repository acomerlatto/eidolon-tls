package eidolon

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/crypto/cryptobyte"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/dns"
	"github.com/acomerlatto/eidolon-tls/internal/order"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// dohConfig is the server of WithDoH.
type dohConfig struct {
	template *dns.Template
	addrs    []string
}

// WithDoH sets the DNS over HTTPS server (RFC 8484) the client asks for
// the HTTPS records (RFC 9460) of its https:// origins, as Chrome with
// secure DNS: the record of an origin gives its ECH configuration, which
// ECHAuto and ECHRequired use. Without WithDoH, a client on Linux that
// connects directly asks the name servers of the system, as Chrome's
// built-in client (see WithECHMode); on other systems, through a proxy or
// WithDialContext, no HTTPS record is looked up and only WithECHConfig
// gives ECH configurations.
//
// template is the URI template of the server: an https:// URL with the
// variable dns ({?dns}, {&dns} or {dns}), whose queries go by GET, or
// without variables, by POST. They go as Chrome sends them: its minimal
// header fields over connections with the profile's ClientHello and
// HTTP/2 settings and GREASE ECH, the certificate verified for the host
// of the template, through the proxy of WithProxy, which resolves that
// host. Without a proxy, addrs are the IP addresses of the server, dialed
// in turn: the server is never looked up in DNS. Redirects are not
// followed, where Chrome follows those to https://.
//
// Over HTTP/2 the queries carry Priority: u=4, i, the IDLE priority of
// most DoH queries of Chrome, the navigations' included, and over
// HTTP/1.1 Connection: keep-alive.
//
// Only the HTTPS records are asked: the addresses of the origins come
// from the proxy, or else from WithDialContext or the system resolver. As
// Chrome, localhost and its subdomains are not asked, nor, without a
// proxy, the names of the hosts file of the system. A lookup that fails or gets no answer within 12 seconds leaves the origin
// without ECH, unless ECHRequired. Answers are kept for their TTL, up to
// 1000 origins per client.
//
// New refuses, with ErrConfig, a template it cannot use, addrs that are
// not IP addresses, no addrs without a proxy, ECHDisabled, and a profile
// that cannot offer ECH.
func WithDoH(template string, addrs ...string) Option {
	return func(c *config) error {
		if c.doh != nil {
			return errors.New("WithDoH: set twice")
		}
		t, err := dns.ParseTemplate(template)
		if err != nil {
			return fmt.Errorf("WithDoH: %w", err)
		}
		for _, a := range addrs {
			if _, err := netip.ParseAddr(a); err != nil {
				return fmt.Errorf("WithDoH: %q is not an IP address", a)
			}
		}
		c.doh = &dohConfig{template: t, addrs: append([]string(nil), addrs...)}
		return nil
	}
}

// configureDoH gives tr a Resolver over the DoH server of the options,
// and returns the transport of its queries, or nil without WithDoH.
func (c *config) configureDoH(tr *dispatch.Transport) (*dispatch.Transport, error) {
	if c.doh == nil {
		return nil, nil
	}
	switch {
	case c.echMode == ECHDisabled:
		return nil, errors.New("WithDoH with ECHDisabled: HTTPS records are only looked up for ECH")
	case c.proxy == nil && len(c.doh.addrs) == 0:
		return nil, errors.New("WithDoH: the addresses of the server are needed without a proxy")
	}
	probe, err := echProbe()
	if err != nil {
		return nil, err
	}
	if err := tlsdial.Check(tlsdial.Config{Spec: tr.Spec, TLS: &utls.Config{EncryptedClientHelloConfigList: probe}}); err != nil {
		return nil, fmt.Errorf("WithDoH: the profile cannot offer ECH: %w", err)
	}
	var pseudo []string
	if c.order != nil {
		pseudo = c.order.Pseudo
	}
	doh := &dispatch.Transport{
		Spec:        tr.Spec,
		TLS:         tr.TLS,
		DialContext: c.dohDial(),
		Proxy:       tr.Proxy,
		// As the captures of Chrome 156: its DoH lookups go at IDLE
		// priority over HTTP/2, and with keep-alive over HTTP/1.1.
		Priority:     "u=4, i",
		H1Connection: "keep-alive",
		// Chrome sends a query again, POST included, when its reused
		// connection is lost.
		Idempotent:      true,
		Order:           &order.Order{Pseudo: pseudo},
		Protocols:       tr.Protocols,
		H2:              tr.H2,
		StrictTLS12:     tr.StrictTLS12,
		MaxConnsPerHost: tr.MaxConnsPerHost,
		IdleConnTimeout: tr.IdleConnTimeout,
	}
	// Through a proxy, the hosts file does not resolve the origins.
	var hosts dns.Config
	if c.proxy == nil {
		hosts, _ = systemDNS()
	}
	tr.Resolver = &dns.Resolver{Exchanger: &dns.DoH{URL: c.doh.template, Transport: doh}, Local: hosts.Local}
	return doh, nil
}

// dohDial returns the dial of the DoH connections: to the proxy, or else
// to the addresses of the server, in turn.
func (c *config) dohDial() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.proxy != nil {
		return c.dialContext
	}
	dial := c.dialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	addrs := c.doh.addrs
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		var err error
		for _, a := range addrs {
			var conn net.Conn
			if conn, err = dial(ctx, network, net.JoinHostPort(a, port)); err == nil {
				return conn, nil
			}
		}
		return nil, err
	}
}

// echProbe returns an ECHConfigList Chrome accepts, to check that a
// profile can offer ECH.
func echProbe() ([]byte, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0xfe0d)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(0)       // config_id
			b.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(1) // HKDF-SHA256
				b.AddUint16(1) // AES-128-GCM
			})
			b.AddUint8(0)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("probe.invalid")) })
			b.AddUint16(0)
		})
	})
	return b.Bytes()
}
