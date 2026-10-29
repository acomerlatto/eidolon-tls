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
	// Host is lowercase ASCII, as the URL standard serializes it: IDN in
	// punycode (UTS #46, non-transitional), IPv4 in dotted decimal whatever
	// form the URL used, IPv6 compressed in hex without brackets. A trailing
	// dot is kept on domains.
	Host string
	// Port is explicit or the scheme default.
	Port int
}

var defaultPorts = map[string]int{"http": 80, "https": 443}

// idnaProfile matches the URL standard's domain to ASCII with beStrict
// false: UTS #46 mapping, non-transitional processing, CheckBidi and
// CheckJoiners on, CheckHyphens and STD3 rules off (underscores and hyphens
// at label edges are allowed). MapForLookup turns CheckHyphens on and
// CheckBidi off, so both are set after it.
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false),
	idna.CheckHyphens(false), idna.BidiRule())

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

// Host returns the host of u as Parse normalizes it, for comparing and
// serializing origins, or u.Hostname() in lowercase if it is not valid.
func Host(u *url.URL) string {
	if h, err := normalizeHost(u.Hostname()); err == nil {
		return h
	}
	return strings.ToLower(u.Hostname())
}

func normalizeHost(h string) (string, error) {
	if h == "" {
		return "", errors.New("target: empty host")
	}
	if strings.Contains(h, "%") {
		return "", fmt.Errorf("target: IPv6 zone in host %q", h)
	}
	if strings.Contains(h, ":") {
		addr, err := netip.ParseAddr(h)
		if err != nil || !addr.Is6() {
			return "", fmt.Errorf("target: invalid IPv6 address %q", h)
		}
		return serializeIPv6(addr), nil
	}
	ascii, err := idnaProfile.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("target: invalid host %q: %w", h, err)
	}
	ascii = strings.ToLower(ascii)
	if endsInNumber(ascii) {
		addr, err := parseIPv4(ascii)
		if err != nil {
			return "", fmt.Errorf("target: invalid IPv4 address %q: %w", h, err)
		}
		return addr.String(), nil
	}
	// Empty labels are refused here rather than by DNS later; only the
	// trailing dot of a fully qualified name is allowed.
	if slices.Contains(strings.Split(strings.TrimSuffix(ascii, "."), "."), "") ||
		!httpguts.ValidHostHeader(ascii) || strings.ContainsAny(ascii, ":/[]@") {
		return "", fmt.Errorf("target: invalid host %q", h)
	}
	return ascii, nil
}

// endsInNumber is the URL standard's ends-in-a-number checker: a host whose
// last label, ignoring a trailing dot, is a number is parsed as IPv4.
func endsInNumber(host string) bool {
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, err := parseIPv4Number(last)
	return err == nil
}

// parseIPv4 is the URL standard's IPv4 parser: one to four parts in
// decimal, octal (leading 0) or hex (leading 0x), the last one filling the
// remaining bytes.
func parseIPv4(host string) (netip.Addr, error) {
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return netip.Addr{}, errors.New("more than four parts")
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, err := parseIPv4Number(p)
		if err != nil {
			return netip.Addr{}, err
		}
		if i < len(parts)-1 && n > 255 {
			return netip.Addr{}, fmt.Errorf("part %q above 255", p)
		}
		nums[i] = n
	}
	last := nums[len(nums)-1]
	if last >= 1<<(8*(5-len(nums))) {
		return netip.Addr{}, fmt.Errorf("last part %d out of range", last)
	}
	ipv4 := last
	for i, n := range nums[:len(nums)-1] {
		ipv4 += n << (8 * (3 - i))
	}
	return netip.AddrFrom4([4]byte{byte(ipv4 >> 24), byte(ipv4 >> 16), byte(ipv4 >> 8), byte(ipv4)}), nil
}

func parseIPv4Number(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty part")
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		s, base = s[2:], 16
	case len(s) >= 2 && s[0] == '0':
		s, base = s[1:], 8
	}
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		// Numbers above 2^64 are out of range for IPv4 anyway.
		if errors.Is(err, strconv.ErrRange) {
			return 1 << 32, nil
		}
		return 0, fmt.Errorf("invalid number %q", s)
	}
	return n, nil
}

// serializeIPv6 is the URL standard's IPv6 serializer: eight hex pieces,
// the first longest run of two or more zero pieces compressed. Unlike
// netip, it never uses dotted IPv4 notation.
func serializeIPv6(addr netip.Addr) string {
	b := addr.As16()
	var pieces [8]uint16
	for i := range pieces {
		pieces[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	start, length := -1, 1
	for i := 0; i < 8; {
		j := i
		for j < 8 && pieces[j] == 0 {
			j++
		}
		if j-i > length {
			start, length = i, j-i
		}
		if j == i {
			j++
		}
		i = j
	}
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		if i == start {
			sb.WriteString("::")
			i += length - 1
			continue
		}
		if sb.Len() > 0 && !strings.HasSuffix(sb.String(), ":") {
			sb.WriteByte(':')
		}
		sb.WriteString(strconv.FormatUint(uint64(pieces[i]), 16))
	}
	return sb.String()
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
// An IPv4-mapped IPv6 address is dialed as IPv4.
func (t Target) Addr() string {
	h := t.Host
	if addr, err := netip.ParseAddr(h); err == nil {
		h = addr.Unmap().String()
	}
	return net.JoinHostPort(h, strconv.Itoa(t.Port))
}

// ServerName is the name the certificate is verified against. uTLS sends it
// as SNI without the trailing dot, and sends no SNI for an IP address. With
// ECH it is the inner (private) name; the outer name comes from the ECH
// configuration.
func (t Target) ServerName() string { return t.Host }
