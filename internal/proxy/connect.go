package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
)

// maxConnectHead bounds the head of a CONNECT response, as Chrome's
// HttpStreamParser bounds response headers (kMaxHeaderBufSize).
const maxConnectHead = 256 << 10

// connect asks for a tunnel as Chrome's HttpProxyClientSocket: the request
// line, Host, Proxy-Connection: keep-alive and the User-Agent of the
// profile when it has one (BuildTunnelRequest). Credentials go in
// Proxy-Authorization: Basic on the first request, where Chrome waits for
// a 407. Only a 200 with nothing after its head opens the tunnel; a 407
// fails with ErrProxyAuth, and the body of any other response is ignored,
// as Chrome ignores it.
func (p *Proxy) connect(conn net.Conn, addr string) error {
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\nProxy-Connection: keep-alive\r\n"
	if p.UserAgent != "" {
		req += "User-Agent: " + p.UserAgent + "\r\n"
	}
	if p.HasAuth {
		req += "Proxy-Authorization: " + p.Authorization() + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		return fmt.Errorf("%w: %w", ErrProxy, err)
	}
	br := bufio.NewReader(io.LimitReader(conn, maxConnectHead))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("%w: CONNECT response: %w", ErrProxy, err)
	}
	switch {
	case resp.StatusCode == http.StatusOK && br.Buffered() == 0:
		return nil
	case resp.StatusCode == http.StatusOK:
		return fmt.Errorf("%w: data after the CONNECT response", ErrProxy)
	case resp.StatusCode == http.StatusProxyAuthRequired:
		return fmt.Errorf("%w: CONNECT status 407", ErrProxyAuth)
	default:
		return fmt.Errorf("%w: CONNECT status %d", ErrProxy, resp.StatusCode)
	}
}

// Authorization returns the Proxy-Authorization value of the credentials:
// Basic, as Chrome's HttpAuthHandlerBasic.
func (p *Proxy) Authorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(p.User+":"+p.Password))
}
