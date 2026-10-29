package proxy

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// The CONNECT request is Chrome's (BuildTunnelRequest): Host, then
// Proxy-Connection and the User-Agent of the profile, with the credentials
// of the URL in Proxy-Authorization: Basic from the first request.
func TestConnect(t *testing.T) {
	ok := []byte("HTTP/1.1 200 Connection established\r\n\r\n")
	for _, tt := range []struct {
		name string
		p    *Proxy
		addr string
		want string
	}{
		{"plain", &Proxy{Scheme: "http"}, "a.test:443",
			"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\nProxy-Connection: keep-alive\r\n\r\n"},
		{"user agent and credentials", &Proxy{Scheme: "http", UserAgent: "UA/1", User: "us:er", Password: "p@ss", HasAuth: true}, "[::1]:8443",
			"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\nProxy-Connection: keep-alive\r\nUser-Agent: UA/1\r\nProxy-Authorization: Basic dXM6ZXI6cEBzcw==\r\n\r\n"},
		{"empty credentials", &Proxy{Scheme: "http", HasAuth: true}, "a.test:80",
			"CONNECT a.test:80 HTTP/1.1\r\nHost: a.test:80\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic Og==\r\n\r\n"},
		{"standard base64", &Proxy{Scheme: "http", User: "???", HasAuth: true}, "a.test:443",
			"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic Pz8/Og==\r\n\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sent, err, after := exchange(t, tt.p, tt.addr, ok)
			if err != nil {
				t.Fatal(err)
			}
			if string(sent) != tt.want {
				t.Errorf("sent %q\nwant %q", sent, tt.want)
			}
			if string(after) != "tail" {
				t.Errorf("read %q after the tunnel, want the server's bytes", after)
			}
		})
	}
}

// Only a 200 with nothing after its head opens the tunnel; a 407 is an
// authentication failure and any other status a proxy failure.
func TestConnectErrors(t *testing.T) {
	noAuth := &Proxy{Scheme: "http"}
	auth := &Proxy{Scheme: "http", User: "u", HasAuth: true}
	for _, tt := range []struct {
		name  string
		p     *Proxy
		reply string
		want  error
	}{
		{"credentials wanted", noAuth, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n", ErrProxyAuth},
		{"credentials refused", auth, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", ErrProxyAuth},
		{"refused", noAuth, "HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno", ErrProxy},
		{"redirect", noAuth, "HTTP/1.1 302 Found\r\nLocation: https://a.test/\r\n\r\n", ErrProxy},
		{"data after", noAuth, "HTTP/1.1 200 OK\r\n\r\nx", ErrProxy},
		{"malformed", noAuth, "SSH-2.0-OpenSSH\r\n\r\n", ErrProxy},
		{"truncated", noAuth, "HTTP/1.1 200 OK\r\n", ErrProxy},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err, _ := exchange(t, tt.p, "a.test:443", []byte(tt.reply))
			if !errors.Is(err, tt.want) || (tt.want == ErrProxy && errors.Is(err, ErrProxyAuth)) {
				t.Errorf("error %v, want %v", err, tt.want)
			}
		})
	}
	// A head of 256 KiB is read, as in Chrome, and a longer one is cut
	// there, with the error of the read.
	long := "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", 256<<10) + "\r\n\r\n"
	if _, err, _ := exchange(t, noAuth, "a.test:443", []byte(long)); !errors.Is(err, ErrProxy) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("head of %d bytes: %v, want ErrProxy and io.ErrUnexpectedEOF", len(long), err)
	}
	reply := "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", 256<<10-len("HTTP/1.1 200 OK\r\nX: \r\n\r\n")) + "\r\n\r\n"
	if _, err, _ := exchange(t, noAuth, "a.test:443", []byte(reply)); err != nil {
		t.Errorf("head of %d bytes: %v", len(reply), err)
	}
}
