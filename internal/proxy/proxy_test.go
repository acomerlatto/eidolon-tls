package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// exchange runs Tunnel to addr against a scripted proxy: it reads what the
// client sends after each reply and sends the next reply, then writes
// "tail" for the client to read after the tunnel. It returns the bytes the
// client sent, the Tunnel error and what the client read after it.
func exchange(t *testing.T, p *Proxy, addr string, replies ...[]byte) (sent []byte, err error, after []byte) {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	var got bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer s.Close()
		buf := make([]byte, 1024)
		for _, r := range replies {
			s.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			for {
				n, err := s.Read(buf)
				got.Write(buf[:n])
				if err != nil || n < len(buf) {
					break
				}
			}
			if _, err := s.Write(r); err != nil {
				return
			}
		}
		s.Write([]byte("tail"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = p.Tunnel(ctx, c, addr)
	if err == nil {
		after = make([]byte, 4)
		io.ReadFull(c, after)
	}
	c.Close()
	<-done
	return got.Bytes(), err, after
}

func mustParse(t *testing.T, raw string) *Proxy {
	t.Helper()
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The SOCKS5 greeting and request are Chrome's (SOCKS5ClientSocket): no
// authentication offered and the name of the destination, an IP address
// as text included. The reply's address is read whole, whatever its type.
func TestSOCKS5(t *testing.T) {
	ok := []byte{5, 0}
	for _, tt := range []struct {
		name  string
		addr  string
		reply []byte
		want  []byte
	}{
		{"name", "example.com:443", []byte{5, 0, 0, 3, 3, 'a', 'b', 'c', 1, 187},
			[]byte{5, 1, 0, 5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187}},
		{"IPv4 as text", "10.0.0.1:80", []byte{5, 0, 0, 1, 1, 2, 3, 4, 0, 80},
			[]byte{5, 1, 0, 5, 1, 0, 3, 8, '1', '0', '.', '0', '.', '0', '.', '1', 0, 80}},
		{"IPv6 reply", "[::1]:8443", append([]byte{5, 0, 0, 4}, make([]byte, 16+2)...),
			[]byte{5, 1, 0, 5, 1, 0, 3, 3, ':', ':', '1', 0x20, 0xfb}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sent, err, after := exchange(t, mustParse(t, "socks5://proxy.test"), tt.addr, ok, tt.reply)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sent, tt.want) {
				t.Errorf("sent %x\nwant %x", sent, tt.want)
			}
			if string(after) != "tail" {
				t.Errorf("read %q after the tunnel, want the server's bytes", after)
			}
		})
	}
}

// With credentials the greeting also offers user/password (RFC 1929).
func TestSOCKS5Auth(t *testing.T) {
	p := mustParse(t, "socks5h://us%3Aer:p%40ss@proxy.test:9050")
	if p.Addr != "proxy.test:9050" {
		t.Errorf("Addr %q", p.Addr)
	}
	sent, err, _ := exchange(t, p, "a.test:443", []byte{5, 2}, []byte{1, 0}, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{5, 2, 0, 2, 1, 5, 'u', 's', ':', 'e', 'r', 4, 'p', '@', 's', 's', 5, 1, 0, 3, 6, 'a', '.', 't', 'e', 's', 't', 1, 187}
	if !bytes.Equal(sent, want) {
		t.Errorf("sent %x\nwant %x", sent, want)
	}
	// The proxy may still accept no authentication.
	if _, err, _ := exchange(t, p, "a.test:443", []byte{5, 0}, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Errorf("no authentication chosen: %v", err)
	}
}

func TestSOCKS5Errors(t *testing.T) {
	noAuth := mustParse(t, "socks5://proxy.test")
	auth := mustParse(t, "socks5://u:p@proxy.test")
	for _, tt := range []struct {
		name    string
		p       *Proxy
		addr    string
		replies [][]byte
		want    error
	}{
		{"credentials wanted", noAuth, "a.test:1", [][]byte{{5, 2}}, ErrProxyAuth},
		{"no method", noAuth, "a.test:1", [][]byte{{5, 0xff}}, ErrProxyAuth},
		{"unknown method", noAuth, "a.test:1", [][]byte{{5, 1}}, ErrProxy},
		{"greeting version", noAuth, "a.test:1", [][]byte{{4, 0}}, ErrProxy},
		{"credentials refused", auth, "a.test:1", [][]byte{{5, 2}, {1, 1}}, ErrProxyAuth},
		{"reply error", noAuth, "a.test:1", [][]byte{{5, 0}, {5, 5, 0, 1, 0, 0, 0, 0, 0, 0}}, ErrProxy},
		{"reply version", noAuth, "a.test:1", [][]byte{{5, 0}, {4, 0, 0, 1, 0, 0, 0, 0, 0, 0}}, ErrProxy},
		{"reply reserved", noAuth, "a.test:1", [][]byte{{5, 0}, {5, 0, 1, 1, 0, 0, 0, 0, 0, 0}}, ErrProxy},
		{"address type", noAuth, "a.test:1", [][]byte{{5, 0}, {5, 0, 0, 2, 0}}, ErrProxy},
		{"closed", noAuth, "a.test:1", [][]byte{{5, 0}, {5, 0, 0}}, ErrProxy},
		{"long name", noAuth, string(bytes.Repeat([]byte("a"), 256)) + ":1", nil, ErrProxy},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err, _ := exchange(t, tt.p, tt.addr, tt.replies...)
			if !errors.Is(err, tt.want) || (tt.want == ErrProxy && errors.Is(err, ErrProxyAuth)) {
				t.Errorf("error %v, want %v", err, tt.want)
			}
		})
	}
}

// SOCKS4 is SOCKS4a: the proxy resolves the name; an IPv4 address goes as
// Chrome sends it. The user ID is the user of the URL, empty without one.
func TestSOCKS4(t *testing.T) {
	ok := []byte{0, 0x5a, 0, 0, 0, 0, 0, 0}
	for _, tt := range []struct {
		raw, addr string
		want      []byte
	}{
		{"socks4://proxy.test", "a.test:443", []byte{4, 1, 1, 187, 0, 0, 0, 1, 0, 'a', '.', 't', 'e', 's', 't', 0}},
		{"socks4a://bob@proxy.test", "a.test:80", []byte{4, 1, 0, 80, 0, 0, 0, 1, 'b', 'o', 'b', 0, 'a', '.', 't', 'e', 's', 't', 0}},
		{"socks4://proxy.test", "10.1.2.3:443", []byte{4, 1, 1, 187, 10, 1, 2, 3, 0}},
	} {
		sent, err, after := exchange(t, mustParse(t, tt.raw), tt.addr, ok)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sent, tt.want) || string(after) != "tail" {
			t.Errorf("%s %s: sent %x, want %x; read %q after", tt.raw, tt.addr, sent, tt.want, after)
		}
	}
	p := mustParse(t, "socks4://proxy.test")
	for _, tt := range []struct {
		name  string
		addr  string
		reply []byte
		want  error
	}{
		{"IPv6", "[::1]:443", nil, ErrProxy},
		{"rejected", "a.test:1", []byte{0, 0x5b, 0, 0, 0, 0, 0, 0}, ErrProxy},
		{"user ID", "a.test:1", []byte{0, 0x5d, 0, 0, 0, 0, 0, 0}, ErrProxyAuth},
		{"version", "a.test:1", []byte{4, 0x5a, 0, 0, 0, 0, 0, 0}, ErrProxy},
		{"short", "a.test:1", []byte{0, 0x5a}, ErrProxy},
	} {
		var replies [][]byte
		if tt.reply != nil {
			replies = append(replies, tt.reply)
		}
		_, err, _ := exchange(t, p, tt.addr, replies...)
		if !errors.Is(err, tt.want) || (tt.want == ErrProxy && errors.Is(err, ErrProxyAuth)) {
			t.Errorf("%s: error %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestParse(t *testing.T) {
	for raw, want := range map[string]Proxy{
		"socks5://p.test":           {Scheme: "socks5", Addr: "p.test:1080"},
		"SOCKS5H://p.test:1":        {Scheme: "socks5", Addr: "p.test:1"},
		"socks4a://[::1]:2/":        {Scheme: "socks4", Addr: "[::1]:2"},
		"socks5://u:@p.test":        {Scheme: "socks5", Addr: "p.test:1080", User: "u", HasAuth: true},
		"socks5://:pw@p.test":       {Scheme: "socks5", Addr: "p.test:1080", Password: "pw", HasAuth: true},
		"socks4://user@10.0.0.1:99": {Scheme: "socks4", Addr: "10.0.0.1:99", User: "user", HasAuth: true},
	} {
		p, err := Parse(raw)
		if err != nil || *p != want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", raw, p, err, want)
		}
	}
	for _, raw := range []string{
		"", "p.test:1080", "ftp://p.test", "socks5://", "socks5://p.test:0", "socks5://p.test:65536",
		"socks5://p.test:x", "socks5://p.test/path", "socks5://p.test?q", "socks5://p.test#f",
		"socks4://u:p@p.test", "socks5://" + string(bytes.Repeat([]byte("u"), 256)) + "@p.test",
		"socks5://u:" + string(bytes.Repeat([]byte("p"), 256)) + "@p.test", "socks5:opaque",
	} {
		if p, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) = %+v, want an error", raw, p)
		}
	}
}

// Tunnel stops when ctx ends, with its error, and leaves the connection
// without deadline after a tunnel.
func TestTunnelContext(t *testing.T) {
	c, s := net.Pipe()
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		io.ReadFull(s, make([]byte, 3))
		cancel()
	}()
	err := mustParse(t, "socks5://p.test").Tunnel(ctx, c, "a.test:1")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v, want context.Canceled", err)
	}
	c.Close()

	c, s = net.Pipe()
	defer s.Close()
	go func() {
		io.ReadFull(s, make([]byte, 3))
		s.Write([]byte{5, 0})
		io.ReadFull(s, make([]byte, 5+6+2))
		s.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		time.Sleep(50 * time.Millisecond)
		s.Write([]byte("x"))
	}()
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := mustParse(t, "socks5://p.test").Tunnel(ctx, c, "a.test:1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Errorf("read after the tunnel: %v; the deadline of ctx stayed", err)
	}
	c.Close()
}

// Tunnel refuses an address without a numeric port before writing.
func TestTunnelAddress(t *testing.T) {
	for _, addr := range []string{"a.test", "a.test:http"} {
		if _, err, _ := exchange(t, mustParse(t, "socks5://p.test"), addr); err == nil {
			t.Errorf("Tunnel(%q) succeeded", addr)
		}
	}
}
