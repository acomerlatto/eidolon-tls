package eidolon_test

import (
	"context"
	"crypto/tls"
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

// An HTTPS proxy gets the ClientHello of the profile with its name and
// ALPN http/1.1 only, then a CONNECT for https:// and the request as it is
// for http://.
func TestProxyHTTPS(t *testing.T) {
	cert, err := lab.NewCertificate(time.Hour, "site.test", "proxy.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{Certificate: &cert})
	plain := lab.Start(t, lab.Options{Certificate: &cert, Plain: true})
	for _, tt := range []struct {
		srv  *lab.Server
		url  string
		head string
	}{
		{srv, "https://site.test/", "CONNECT site.test:443 HTTP/1.1\r\n"},
		{plain, "http://site.test/", "GET http://site.test/ HTTP/1.1\r\n"},
	} {
		p := lab.StartHTTPSProxy(t, tt.srv.Addr, "Basic dXNlcjpwYXNz", cert)
		var dialed []string
		c := proxyClient(t, tt.srv, "https://user:pass@proxy.test", eidolon.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			var d net.Dialer
			return d.DialContext(ctx, network, p.Addr)
		}))
		if _, err := echGet(c, tt.url); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(dialed, []string{"proxy.test:443"}) {
			t.Errorf("%s: dialed %q, want the proxy on 443", tt.url, dialed)
		}
		hellos := p.Hellos()
		if len(hellos) != 1 || hellos[0].ServerName != "proxy.test" || !slices.Equal(hellos[0].SupportedProtos, []string{"http/1.1"}) {
			t.Fatalf("%s: hellos %+v, want proxy.test with http/1.1", tt.url, hellos)
		}
		if heads := p.Heads(); len(heads) != 1 || !strings.HasPrefix(heads[0], tt.head) || !strings.Contains(heads[0], "\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n") {
			t.Errorf("%s: heads %q, want %q with the credentials", tt.url, heads, tt.head)
		}
	}
	// An IP address is verified against the certificate and sent without
	// SNI, as Chrome.
	p := lab.StartHTTPSProxy(t, srv.Addr, "", cert)
	if _, err := echGet(proxyClient(t, srv, "https://"+p.Addr), "https://site.test/"); err != nil {
		t.Fatal(err)
	}
	if hellos := p.Hellos(); len(hellos) != 1 || hellos[0].ServerName != "" {
		t.Errorf("hellos %+v, want one without SNI", hellos)
	}
	// StrictTLS12 applies to the proxy.
	rsaCert := rsaCertificate(t)
	srv.RootCAs.AddCert(rsaCert.Leaf)
	p = lab.StartHTTPSProxy(t, srv.Addr, "", *rsaCert, func(c *tls.Config) {
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}
	})
	_, err = echGet(proxyClient(t, srv, "https://"+p.Addr, eidolon.WithStrictTLS12()), "https://site.test/")
	if !errors.Is(err, eidolon.ErrProxy) || !errors.Is(err, eidolon.ErrTLS12Policy) {
		t.Errorf("weak proxy: %v, want ErrProxy and ErrTLS12Policy", err)
	}
	// The certificate of the proxy is verified.
	other, err := lab.NewCertificate(time.Hour, "proxy.test")
	if err != nil {
		t.Fatal(err)
	}
	p = lab.StartHTTPSProxy(t, srv.Addr, "", other)
	_, err = echGet(proxyClient(t, srv, "https://"+p.Addr), "https://site.test/")
	if !errors.Is(err, eidolon.ErrProxy) || !errors.Is(err, eidolon.ErrCertificate) {
		t.Errorf("untrusted proxy: %v, want ErrProxy and ErrCertificate", err)
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

// With WithNewConnectionPerRequest each request opens a tunnel of its
// own, closed when its body ends, HEAD included; without it, one tunnel
// carries them all.
func TestProxyNewConnectionPerRequest(t *testing.T) {
	for _, perRequest := range []bool{false, true} {
		srv, p := proxyLab(t, "", "", "site.test")
		var opts []eidolon.Option
		if perRequest {
			opts = append(opts, eidolon.WithNewConnectionPerRequest())
		}
		c := proxyClient(t, srv, "socks5://"+p.Addr, opts...)
		for range 3 {
			if _, err := echGet(c, "https://site.test/"); err != nil {
				t.Fatal(err)
			}
		}
		if perRequest {
			for range 3 {
				select {
				case <-srv.NextConn(t).Done():
				case <-time.After(5 * time.Second):
					t.Fatal("a connection stayed open after its response")
				}
			}
			resp, err := c.Head("https://site.test/")
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-srv.NextConn(t).Done():
			case <-time.After(5 * time.Second):
				t.Fatalf("the connection of a HEAD (%v) stayed open", resp.Body == http.NoBody)
			}
		}
		want := 1
		if perRequest {
			want = 4
		}
		if n := len(p.Destinations()); n != want {
			t.Errorf("per request %v: %d tunnels, want %d", perRequest, n, want)
		}
	}
}

// Close ends a response in progress of WithNewConnectionPerRequest.
func TestNewConnectionPerRequestClose(t *testing.T) {
	srv, p := proxyLab(t, "", "", "site.test")
	c := proxyClient(t, srv, "socks5://"+p.Addr, eidolon.WithNewConnectionPerRequest())
	resp, err := c.Get("https://site.test/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	c.Close()
	select {
	case <-srv.NextConn(t).Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Close left the connection open")
	}
	if _, err := c.Get("https://site.test/"); !errors.Is(err, eidolon.ErrClosed) {
		t.Errorf("after Close: %v, want ErrClosed", err)
	}
}

// Through every kind of proxy, the ClientHello and the HTTP/2 preface of
// the destination are those of a direct connection.
func TestProxySameAsDirect(t *testing.T) {
	cert, err := lab.NewCertificate(time.Hour, "site.test", "proxy.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{Certificate: &cert})
	describe := func(c eidolon.HttpClient) (hello, ja4, akamai string) {
		t.Helper()
		if _, err := echGet(c, "https://site.test/"); err != nil {
			t.Fatal(err)
		}
		conn := srv.NextConn(t)
		frames, err := conn.H2Frames()
		if err != nil {
			t.Fatal(err)
		}
		var first [][2]string
		for _, fr := range frames {
			if fr.Type == "HEADERS" {
				first = fields(fr)
				break
			}
		}
		h := parseHello(t, conn.ClientHello)
		return normalHello(h), h.JA4(), akamaiOf(frames, first)
	}
	direct, err := eidolon.New(eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithRootCAs(srv.RootCAs),
		eidolon.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Addr)
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	wantHello, wantJA4, wantAkamai := describe(direct)
	for _, rawURL := range []string{
		"socks5://" + lab.StartSOCKS(t, srv.Addr, "", "").Addr,
		"http://" + lab.StartHTTPProxy(t, srv.Addr, "").Addr,
		"https://" + lab.StartHTTPSProxy(t, srv.Addr, "", cert).Addr,
	} {
		hello, ja4, akamai := describe(proxyClient(t, srv, rawURL))
		if hello != wantHello || ja4 != wantJA4 || akamai != wantAkamai {
			t.Errorf("%s: ClientHello\n%s\nJA4 %s, Akamai %s; want\n%s\nJA4 %s, Akamai %s", rawURL, hello, ja4, akamai, wantHello, wantJA4, wantAkamai)
		}
	}
}
