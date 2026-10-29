// Package proxy opens tunnels through a proxy as Chrome 156 does, with the
// deviations a crawler needs: credentials from the URL and the name of the
// destination always resolved by the proxy.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// ErrProxy reports a proxy that could not be reached or refused the
// tunnel. No byte of the request reaches the destination.
var ErrProxy = errors.New("eidolon: proxy failed")

// ErrProxyAuth reports a proxy that refused the credentials of its URL, or
// asked for credentials the URL does not have.
var ErrProxyAuth = errors.New("eidolon: proxy authentication failed")

// Proxy is a parsed proxy URL.
type Proxy struct {
	// Scheme is socks4 (SOCKS4a), socks5, or http and https (CONNECT).
	Scheme string
	// Addr is the host:port of the proxy.
	Addr string
	// User and Password are the credentials of the URL; HasAuth reports
	// a URL with them.
	User, Password string
	HasAuth        bool
	// UserAgent is sent in the CONNECT requests; "" sends none.
	UserAgent string
}

// Parse parses a proxy URL: http://, https://, socks4://, socks4a:// and
// socks5:// or socks5h://, with an optional user:password@ and port, 80
// for http://, 443 for https:// and 1080 for SOCKS by default as in Chrome
// (GetDefaultPortForSchemeTyped).
// socks4:// is taken as SOCKS4a, and socks5:// sends the name, as Chrome's:
// the proxy resolves the destination. SOCKS4 has no password.
func Parse(raw string) (*Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	p := &Proxy{}
	port := "1080"
	switch u.Scheme {
	case "http":
		p.Scheme, port = "http", "80"
	case "https":
		p.Scheme, port = "https", "443"
	case "socks4", "socks4a":
		p.Scheme = "socks4"
	case "socks5", "socks5h":
		p.Scheme = "socks5"
	default:
		return nil, fmt.Errorf("proxy %q: unsupported scheme %q", u.Redacted(), u.Scheme)
	}
	if u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("proxy %q: want scheme://[user:password@]host[:port]", u.Redacted())
	}
	if u.Port() != "" {
		port = u.Port()
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("proxy %q: invalid port %q", u.Redacted(), port)
		}
	}
	p.Addr = net.JoinHostPort(u.Hostname(), port)
	if u.User != nil {
		p.HasAuth = true
		p.User = u.User.Username()
		p.Password, _ = u.User.Password()
		if p.Scheme == "socks5" && (len(p.User) > 255 || len(p.Password) > 255) {
			return nil, fmt.Errorf("proxy %q: user or password longer than 255 bytes", u.Redacted())
		}
		if _, ok := u.User.Password(); ok && p.Scheme == "socks4" {
			return nil, fmt.Errorf("proxy %q: SOCKS4 has no password", u.Redacted())
		}
	}
	return p, nil
}

// Tunnel asks the proxy, over conn, for a tunnel to addr, a host:port.
// The end of ctx stops the exchange.
func (p *Proxy) Tunnel(ctx context.Context, conn net.Conn, addr string) error {
	// A malformed addr leaves portStr empty, which Atoi refuses.
	host, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	switch p.Scheme {
	case "socks4":
		err = p.socks4(conn, host, port)
	case "http", "https":
		err = p.connect(conn, addr)
	default:
		err = p.socks5(conn, host, port)
	}
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
