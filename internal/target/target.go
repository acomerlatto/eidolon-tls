// Package target normalizes the destination of a request into one identity
// shared by the dialer, the TLS verification and the HTTP engines.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/idna"
)

// Target is a normalized destination.
type Target struct {
	// Scheme is "http" or "https".
	Scheme string
	// Host is lowercase ASCII: IDN in punycode (UTS #46, non-transitional,
	// as Chrome), IP addresses in canonical form, IPv6 without brackets. A
	// trailing dot is kept.
	Host string
	// Port is explicit or the scheme default.
	Port int
}

var defaultPorts = map[string]int{"http": 80, "https": 443}

// idnaProfile matches the URL standard's domain to ASCII: UTS #46 mapping,
// non-transitional processing, no STD3 rules (underscores are allowed).
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false))

// Parse normalizes the scheme, host and port of u. Userinfo, path and query
// are not part of the identity.
func Parse(u *url.URL) (Target, error) {
	if u == nil {
		return Target{}, errors.New("target: URL is nil")
	}
	scheme := strings.ToLower(u.Scheme)
	defPort, ok := defaultPorts[scheme]
	if !ok {
		return Target{}, fmt.Errorf("target: unsupported scheme %q", u.Scheme)
	}
	host, err := normalizeHost(u.Hostname())
	if err != nil {
		return Target{}, err
	}
	port := defPort
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Target{}, fmt.Errorf("target: invalid port %q", p)
		}
		port = n
	}
	return Target{Scheme: scheme, Host: host, Port: port}, nil
}

func normalizeHost(h string) (string, error) {
	if h == "" {
		return "", errors.New("target: empty host")
	}
	if strings.Contains(h, "%") {
		return "", fmt.Errorf("target: IPv6 zone in host %q", h)
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return addr.Unmap().String(), nil
	}
	ascii, err := idnaProfile.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("target: invalid host %q: %w", h, err)
	}
	ascii = strings.ToLower(ascii)
	// Empty labels are refused here rather than by DNS later; only the
	// trailing dot of a fully qualified name is allowed.
	if slices.Contains(strings.Split(strings.TrimSuffix(ascii, "."), "."), "") ||
		!httpguts.ValidHostHeader(ascii) || strings.ContainsAny(ascii, ":/[]@") {
		return "", fmt.Errorf("target: invalid host %q", h)
	}
	return ascii, nil
}

// IsIP reports whether Host is an IP address.
func (t Target) IsIP() bool {
	_, err := netip.ParseAddr(t.Host)
	return err == nil
}

// DefaultPort reports whether Port is the scheme default.
func (t Target) DefaultPort() bool { return t.Port == defaultPorts[t.Scheme] }

// Authority is the host and port sent as Host (HTTP/1.1) and :authority
// (HTTP/2). The default port is omitted, as the URL standard does; IPv6 is
// bracketed.
func (t Target) Authority() string {
	h := t.Host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	if t.DefaultPort() {
		return h
	}
	return h + ":" + strconv.Itoa(t.Port)
}

// Origin is scheme://authority, the key of pools and caches.
func (t Target) Origin() string { return t.Scheme + "://" + t.Authority() }

// Addr is the TCP endpoint to dial before any DNS-based endpoint selection.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// ServerName is the name the certificate is verified against. uTLS sends it
// as SNI without the trailing dot, and sends no SNI for an IP address. With
// ECH it is the inner (private) name; the outer name comes from the ECH
// configuration.
func (t Target) ServerName() string { return t.Host }
