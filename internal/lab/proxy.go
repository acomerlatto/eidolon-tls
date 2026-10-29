package lab

import (
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
)

// SOCKSProxy is a SOCKS4a and SOCKS5 proxy for tests. It records the
// destination of each tunnel and forwards the tunnel to Upstream,
// whatever the destination, as a lab server answers for any name.
type SOCKSProxy struct {
	// Addr is the listening address, on 127.0.0.1.
	Addr string
	// Upstream is the address every tunnel goes to.
	Upstream string
	// User and Password, when User is set, are required: by RFC 1929 in
	// SOCKS5 and as the user ID in SOCKS4.
	User, Password string

	ln   net.Listener
	mu   sync.Mutex
	dest []string
	wg   sync.WaitGroup
}

// StartSOCKS starts a SOCKS proxy to upstream, closed when the test ends.
func StartSOCKS(tb testing.TB, upstream, user, password string) *SOCKSProxy {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	p := &SOCKSProxy{Addr: ln.Addr().String(), Upstream: upstream, User: user, Password: password, ln: ln}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				p.serve(c)
			}()
		}
	}()
	tb.Cleanup(func() {
		ln.Close()
		p.wg.Wait()
	})
	return p
}

// Destinations returns the host:port of each tunnel asked for, in order.
func (p *SOCKSProxy) Destinations() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.dest...)
}

func (p *SOCKSProxy) serve(c net.Conn) {
	defer c.Close()
	var ver [1]byte
	if _, err := io.ReadFull(c, ver[:]); err != nil {
		return
	}
	var dest string
	var ok bool
	switch ver[0] {
	case 4:
		dest, ok = p.socks4(c)
	case 5:
		dest, ok = p.socks5(c)
	}
	if !ok {
		return
	}
	p.mu.Lock()
	p.dest = append(p.dest, dest)
	p.mu.Unlock()
	up, err := net.Dial("tcp", p.Upstream)
	if err != nil {
		return
	}
	defer up.Close()
	go func() {
		io.Copy(up, c)
		up.Close()
	}()
	io.Copy(c, up)
}

// socks4 reads a SOCKS4 or SOCKS4a request after its version.
func (p *SOCKSProxy) socks4(c net.Conn) (string, bool) {
	var head [7]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", false
	}
	user, ok := readCString(c)
	if !ok {
		return "", false
	}
	host := net.IP(head[3:7]).String()
	if head[3] == 0 && head[4] == 0 && head[5] == 0 && head[6] != 0 {
		if host, ok = readCString(c); !ok {
			return "", false
		}
	}
	code := byte(0x5a)
	if p.User != "" && user != p.User {
		code = 0x5d
	}
	c.Write([]byte{0, code, 0, 0, 0, 0, 0, 0})
	return net.JoinHostPort(host, strconv.Itoa(int(head[1])<<8|int(head[2]))), code == 0x5a
}

// socks5 reads a SOCKS5 greeting after its version, and the request.
func (p *SOCKSProxy) socks5(c net.Conn) (string, bool) {
	var n [1]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return "", false
	}
	methods := make([]byte, n[0])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", false
	}
	if p.User == "" {
		c.Write([]byte{5, 0})
	} else {
		c.Write([]byte{5, 2})
		var v [2]byte
		if _, err := io.ReadFull(c, v[:]); err != nil {
			return "", false
		}
		user := make([]byte, v[1])
		io.ReadFull(c, user)
		var pl [1]byte
		io.ReadFull(c, pl[:])
		pass := make([]byte, pl[0])
		if _, err := io.ReadFull(c, pass); err != nil {
			return "", false
		}
		if string(user) != p.User || string(pass) != p.Password {
			c.Write([]byte{1, 1})
			return "", false
		}
		c.Write([]byte{1, 0})
	}
	var head [5]byte
	if _, err := io.ReadFull(c, head[:]); err != nil || head[3] != 3 {
		return "", false
	}
	rest := make([]byte, int(head[4])+2)
	if _, err := io.ReadFull(c, rest); err != nil {
		return "", false
	}
	host := string(rest[:head[4]])
	port := int(rest[head[4]])<<8 | int(rest[head[4]+1])
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	return net.JoinHostPort(host, strconv.Itoa(port)), true
}

// readCString reads a NUL-terminated string.
func readCString(c net.Conn) (string, bool) {
	var b []byte
	var one [1]byte
	for len(b) < 256 {
		if _, err := io.ReadFull(c, one[:]); err != nil {
			return "", false
		}
		if one[0] == 0 {
			return string(b), true
		}
		b = append(b, one[0])
	}
	return "", false
}
