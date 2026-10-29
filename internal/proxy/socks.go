package proxy

import (
	"fmt"
	"io"
	"net"
	"net/netip"
)

// socks4 asks for a tunnel as Chrome's SOCKSClientSocket, as SOCKS4a: Chrome
// resolves the name itself and sends its first IPv4 address, while here the
// proxy resolves it (IP 0.0.0.1, the name after the user ID). An IPv4
// address is sent as Chrome sends it. The user ID is the user of the URL,
// empty as in Chrome without one.
func (p *Proxy) socks4(conn net.Conn, host string, port int) error {
	req := []byte{4, 1, byte(port >> 8), byte(port)}
	ip, err := netip.ParseAddr(host)
	switch {
	case err != nil:
		req = append(req, 0, 0, 0, 1)
	case ip.Is4():
		req = append(req, ip.AsSlice()...)
	default:
		return fmt.Errorf("%w: SOCKS4 cannot reach the IPv6 address %s", ErrProxy, host)
	}
	req = append(req, p.User...)
	req = append(req, 0)
	if err != nil {
		req = append(req, host...)
		req = append(req, 0)
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("%w: %w", ErrProxy, err)
	}
	var resp [8]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrProxy, err)
	}
	if resp[0] != 0 {
		return fmt.Errorf("%w: SOCKS4 reply version %d", ErrProxy, resp[0])
	}
	switch resp[1] {
	case 0x5a:
		return nil
	case 0x5d:
		return fmt.Errorf("%w: SOCKS4 user ID refused", ErrProxyAuth)
	default:
		return fmt.Errorf("%w: SOCKS4 reply %#x", ErrProxy, resp[1])
	}
}

// socks5 asks for a tunnel as Chrome's SOCKS5ClientSocket: the greeting
// offers no authentication, 05 01 00, and the request carries the name of
// the destination, an IP address as text included, for the proxy to
// resolve. With credentials, which Chrome does not support, the greeting
// also offers user/password (RFC 1929), as curl does.
func (p *Proxy) socks5(conn net.Conn, host string, port int) error {
	if len(host) > 255 {
		return fmt.Errorf("%w: host name longer than 255 bytes", ErrProxy)
	}
	greet := []byte{5, 1, 0}
	if p.HasAuth {
		greet = []byte{5, 2, 0, 2}
	}
	if _, err := conn.Write(greet); err != nil {
		return fmt.Errorf("%w: %w", ErrProxy, err)
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrProxy, err)
	}
	if method[0] != 5 {
		return fmt.Errorf("%w: SOCKS5 greeting version %d", ErrProxy, method[0])
	}
	switch {
	case method[1] == 0:
	case method[1] == 2 && p.HasAuth:
		if err := p.socks5Auth(conn); err != nil {
			return err
		}
	case method[1] == 2 || method[1] == 0xff:
		return fmt.Errorf("%w: SOCKS5 proxy wants credentials", ErrProxyAuth)
	default:
		return fmt.Errorf("%w: SOCKS5 method %#x", ErrProxy, method[1])
	}

	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("%w: %w", ErrProxy, err)
	}
	// As Chrome, 5 bytes first: the fourth is the address type and the
	// fifth, with a name, its length.
	var head [5]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrProxy, err)
	}
	if head[0] != 5 || head[2] != 0 {
		return fmt.Errorf("%w: SOCKS5 reply version %d", ErrProxy, head[0])
	}
	if head[1] != 0 {
		return fmt.Errorf("%w: SOCKS5 reply %#x", ErrProxy, head[1])
	}
	var rest int
	switch head[3] {
	case 3:
		rest = int(head[4])
	case 1:
		rest = 4 - 1
	case 4:
		rest = 16 - 1
	default:
		return fmt.Errorf("%w: SOCKS5 address type %d", ErrProxy, head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, rest+2)); err != nil {
		return fmt.Errorf("%w: %w", ErrProxy, err)
	}
	return nil
}

// socks5Auth sends the user and password of the URL (RFC 1929).
func (p *Proxy) socks5Auth(conn net.Conn) error {
	req := []byte{1, byte(len(p.User))}
	req = append(req, p.User...)
	req = append(req, byte(len(p.Password)))
	req = append(req, p.Password...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("%w: %w", ErrProxy, err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrProxy, err)
	}
	if resp[1] != 0 {
		return fmt.Errorf("%w: SOCKS5 credentials refused", ErrProxyAuth)
	}
	return nil
}
