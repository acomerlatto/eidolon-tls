package eidolon_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// proxyLab starts a lab server for the names, and a SOCKS proxy to it.
func proxyLab(t *testing.T, user, password string, names ...string) (*lab.Server, *lab.SOCKSProxy) {
	t.Helper()
	cert, err := lab.NewCertificate(time.Hour, names...)
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{Certificate: &cert})
	return srv, lab.StartSOCKS(t, srv.Addr, user, password)
}

// proxyClient returns a Chrome client through rawURL.
func proxyClient(t *testing.T, srv *lab.Server, rawURL string, opts ...eidolon.Option) eidolon.HttpClient {
	t.Helper()
	c, err := eidolon.New(append([]eidolon.Option{
		eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithRootCAs(srv.RootCAs), eidolon.WithProxy(rawURL),
	}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// Through a SOCKS proxy, https:// and http:// go over a tunnel to the name
// of the destination, which the proxy resolves; the TLS connection is the
// direct one.
func TestProxySOCKS(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h", "socks4", "socks4a"} {
		t.Run(scheme, func(t *testing.T) {
			srv, p := proxyLab(t, "", "", "site.test")
			c := proxyClient(t, srv, scheme+"://"+p.Addr)
			resp, err := echGet(c, "https://site.test/")
			if err != nil {
				t.Fatal(err)
			}
			conn := srv.NextConn(t)
			if resp.Proto != "HTTP/2.0" || conn.State.ServerName != "site.test" {
				t.Errorf("protocol %s, server name %q", resp.Proto, conn.State.ServerName)
			}
			if got := p.Destinations(); !slices.Equal(got, []string{"site.test:443"}) {
				t.Errorf("tunnels to %q, want site.test:443", got)
			}
		})
	}
	// http:// goes over a tunnel too.
	cert, err := lab.NewCertificate(time.Hour, "site.test")
	if err != nil {
		t.Fatal(err)
	}
	plain := lab.Start(t, lab.Options{Certificate: &cert, Plain: true})
	p := lab.StartSOCKS(t, plain.Addr, "", "")
	c := proxyClient(t, plain, "socks5://"+p.Addr)
	if _, err := echGet(c, "http://site.test:8080/"); err != nil {
		t.Fatal(err)
	}
	if got := p.Destinations(); !slices.Equal(got, []string{"site.test:8080"}) {
		t.Errorf("tunnels to %q, want site.test:8080", got)
	}
}

// The credentials of the URL authenticate to the proxy; a refusal, or a
// proxy that wants credentials the URL does not have, fails the request
// with ErrProxyAuth.
func TestProxySOCKSAuth(t *testing.T) {
	srv, p := proxyLab(t, "user", "pass", "site.test")
	if _, err := echGet(proxyClient(t, srv, "socks5://user:pass@"+p.Addr), "https://site.test/"); err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{"socks5://user:wrong@" + p.Addr, "socks5://" + p.Addr, "socks4://bob@" + p.Addr} {
		_, err := echGet(proxyClient(t, srv, rawURL), "https://site.test/")
		if !errors.Is(err, eidolon.ErrProxyAuth) {
			t.Errorf("%s: %v, want ErrProxyAuth", rawURL, err)
		}
	}
	if n := srv.Accepted(); n != 1 {
		t.Errorf("%d connections reached the server, want 1", n)
	}
}

// A proxy that cannot be reached fails the request with ErrProxy, and
// WithDialContext opens the connection to the proxy.
func TestProxyDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	srv, p := proxyLab(t, "", "", "site.test")
	if _, err := echGet(proxyClient(t, srv, "socks5://"+dead), "https://site.test/"); !errors.Is(err, eidolon.ErrProxy) {
		t.Errorf("unreachable proxy: %v, want ErrProxy", err)
	}

	var mu sync.Mutex
	var dialed []string
	c := proxyClient(t, srv, "socks5://proxy.test:1080", eidolon.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, p.Addr)
	}))
	if _, err := echGet(c, "https://site.test/"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(dialed, []string{"proxy.test:1080"}) {
		t.Errorf("dialed %q, want the proxy", dialed)
	}
}

// Behind a proxy, the retry of a rejected ECH asks the proxy for the name
// again: the address of the rejected connection is the proxy's.
func TestProxyECHRetry(t *testing.T) {
	srv, stale := echRejectingLab(t, []string{echSecret, echPublic})
	p := lab.StartSOCKS(t, srv.Addr, "", "")
	c := proxyClient(t, srv, "socks5://"+p.Addr, eidolon.WithECHConfig(echSecret, stale))
	if _, err := echGet(c, "https://"+echSecret+"/"); err != nil {
		t.Fatal(err)
	}
	checkRejected(t, srv.NextConn(t))
	want := []string{echSecret + ":443", echSecret + ":443"}
	if got := p.Destinations(); !slices.Equal(got, want) {
		t.Errorf("tunnels to %q, want %q", got, want)
	}
}

// Through an HTTP proxy, https:// goes over a CONNECT tunnel as Chrome
// asks for it, with the User-Agent of the profile and the credentials of
// the URL; the TLS connection is the direct one.
func TestProxyHTTPConnect(t *testing.T) {
	cert, err := lab.NewCertificate(time.Hour, "site.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{Certificate: &cert})
	p := lab.StartHTTPProxy(t, srv.Addr, "Basic dXNlcjpwYXNz")
	resp, err := echGet(proxyClient(t, srv, "http://user:pass@"+p.Addr), "https://site.test/")
	if err != nil {
		t.Fatal(err)
	}
	conn := srv.NextConn(t)
	if resp.Proto != "HTTP/2.0" || conn.State.ServerName != "site.test" {
		t.Errorf("protocol %s, server name %q", resp.Proto, conn.State.ServerName)
	}
	want := "CONNECT site.test:443 HTTP/1.1\r\nHost: site.test:443\r\nProxy-Connection: keep-alive\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
	if got := p.Heads(); !slices.Equal(got, []string{want}) {
		t.Errorf("heads %q\nwant %q", got, want)
	}
	// Over HTTP/1.1 in the tunnel, the request is the direct one.
	resp, err = echGet(proxyClient(t, srv, "http://user:pass@"+p.Addr, eidolon.WithForceHTTP1()), "https://site.test/")
	if err != nil {
		t.Fatal(err)
	}
	got := string(srv.NextConn(t).Bytes())
	if resp.Proto != "HTTP/1.1" || !strings.HasPrefix(got, "GET / HTTP/1.1\r\nHost: site.test\r\nConnection: keep-alive\r\n") || strings.Contains(got, "Proxy-") {
		t.Errorf("protocol %s, the server got %q", resp.Proto, got)
	}
}

// Through an HTTP proxy, http:// goes to the proxy as it is, as Chrome
// sends it: the absolute URL in the request line, Proxy-Connection in
// place of Connection and Proxy-Authorization after it.
func TestProxyHTTPForward(t *testing.T) {
	cert, err := lab.NewCertificate(time.Hour, "site.test")
	if err != nil {
		t.Fatal(err)
	}
	plain := lab.Start(t, lab.Options{Certificate: &cert, Plain: true})
	p := lab.StartHTTPProxy(t, plain.Addr, "Basic dXNlcjpwYXNz")
	c := proxyClient(t, plain, "http://user:pass@"+p.Addr)
	if _, err := echGet(c, "http://site.test:8080/a?b"); err != nil {
		t.Fatal(err)
	}
	heads := p.Heads()
	if len(heads) != 1 {
		t.Fatalf("heads %q, want one", heads)
	}
	want := "GET http://site.test:8080/a?b HTTP/1.1\r\nHost: site.test:8080\r\nProxy-Connection: keep-alive\r\n" +
		"Proxy-Authorization: Basic dXNlcjpwYXNz\r\nUpgrade-Insecure-Requests: 1\r\n"
	if !strings.HasPrefix(heads[0], want) || strings.Contains(heads[0], "\nConnection:") {
		t.Errorf("head %q\nwant it to start with %q, without Connection", heads[0], want)
	}
	if got := string(plain.NextConn(t).Bytes()); !strings.HasPrefix(got, heads[0]) {
		t.Errorf("the server got %q, want the request as the proxy got it", got)
	}
}

// An HTTP proxy that refuses the credentials fails the request with
// ErrProxyAuth, in a CONNECT and for a request it forwards.
func TestProxyHTTPAuth(t *testing.T) {
	cert, err := lab.NewCertificate(time.Hour, "site.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{Certificate: &cert})
	plain := lab.Start(t, lab.Options{Certificate: &cert, Plain: true})
	for _, tt := range []struct {
		srv *lab.Server
		url string
	}{{srv, "https://site.test/"}, {plain, "http://site.test/"}} {
		p := lab.StartHTTPProxy(t, tt.srv.Addr, "Basic dXNlcjpwYXNz")
		for _, rawURL := range []string{"http://user:wrong@" + p.Addr, "http://" + p.Addr} {
			_, err := echGet(proxyClient(t, tt.srv, rawURL), tt.url)
			if !errors.Is(err, eidolon.ErrProxyAuth) {
				t.Errorf("%s through %s: %v, want ErrProxyAuth", tt.url, rawURL, err)
			}
		}
		if n := tt.srv.Accepted(); n != 0 {
			t.Errorf("%s: %d connections reached the server, want 0", tt.url, n)
		}
	}
}

// A 407 of the server, not of a proxy that forwards the request, is a
// response.
func TestProxyServer407(t *testing.T) {
	cert, err := lab.NewCertificate(time.Hour, "site.test")
	if err != nil {
		t.Fatal(err)
	}
	plain := lab.Start(t, lab.Options{Certificate: &cert, Plain: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
	})})
	p := lab.StartSOCKS(t, plain.Addr, "", "")
	resp, err := echGet(proxyClient(t, plain, "socks5://"+p.Addr), "http://site.test/")
	if err != nil || resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status %v, %v; want the 407", resp, err)
	}
}

// New refuses a proxy URL it cannot use, and a second WithProxy.
func TestProxyConfig(t *testing.T) {
	for _, opts := range [][]eidolon.Option{
		{eidolon.WithProxy("ftp://p.test")},
		{eidolon.WithProxy("socks4://u:p@p.test")},
		{eidolon.WithProxy("socks5://p.test"), eidolon.WithProxy("socks5://q.test")},
	} {
		if _, err := eidolon.New(append([]eidolon.Option{eidolon.WithClientHello(chromeSpec)}, opts...)...); !errors.Is(err, eidolon.ErrConfig) {
			t.Errorf("New: %v, want ErrConfig", err)
		}
	}
}
