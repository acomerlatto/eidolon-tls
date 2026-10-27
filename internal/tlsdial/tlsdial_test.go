package tlsdial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/http2"
)

const (
	extCompressCertificate = 27
	extALPSNew             = 17613
)

func chromeSpec() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
	return &spec, err
}

// specWithALPN is a small TLS 1.3 spec that offers the given ALPN protocols.
func specWithALPN(protos ...string) func() (*utls.ClientHelloSpec, error) {
	return func() (*utls.ClientHelloSpec, error) {
		return &utls.ClientHelloSpec{
			TLSVersMin:         utls.VersionTLS13,
			TLSVersMax:         utls.VersionTLS13,
			CipherSuites:       []uint16{utls.TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
			Extensions: []utls.TLSExtension{
				&utls.SNIExtension{},
				&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519}},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256}},
				&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
				&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
				&utls.ALPNExtension{AlpnProtocols: protos},
			},
		}, nil
	}
}

// helloRecorder keeps the ClientHello seen by the server.
type helloRecorder struct {
	mu    sync.Mutex
	hello *tls.ClientHelloInfo
}

func (r *helloRecorder) get() *tls.ClientHelloInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hello
}

// newTLSServer starts an HTTPS server offering nextProtos. HTTP/2 is served
// when nextProtos contains "h2".
func newTLSServer(t *testing.T, nextProtos []string, h http.Handler) (*httptest.Server, *helloRecorder) {
	t.Helper()
	rec := &helloRecorder{}
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = slices.Contains(nextProtos, ProtoH2)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failures
	srv.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			rec.mu.Lock()
			rec.hello = hello
			rec.mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	srv.TLS.NextProtos = nextProtos
	t.Cleanup(srv.Close)
	return srv, rec
}

func tlsConfig(srv *httptest.Server, serverName string) *utls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return &utls.Config{ServerName: serverName, RootCAs: roots}
}

// closeCounter wraps the dialed connections and counts Close calls.
type closeCounter struct {
	dialed, closed atomic.Int32
}

func (c *closeCounter) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	c.dialed.Add(1)
	return &countedConn{Conn: conn, c: c}, nil
}

func (c *closeCounter) check(t *testing.T) {
	t.Helper()
	if d, cl := c.dialed.Load(), c.closed.Load(); d != 1 || cl < 1 {
		t.Errorf("dialed %d connections, closed %d; want the connection closed", d, cl)
	}
}

type countedConn struct {
	net.Conn
	c *closeCounter
}

func (c *countedConn) Close() error {
	c.c.closed.Add(1)
	return c.Conn.Close()
}

// Spike for M0: Chrome spec -> handshake -> ALPN h2 -> internal HTTP/2
// engine -> GET.
func TestChromeSpecH2RoundTrip(t *testing.T) {
	srv, rec := newTLSServer(t, []string{ProtoH2, ProtoHTTP1}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.TLS == nil || r.TLS.NegotiatedProtocol != ProtoH2 {
			http.Error(w, "not HTTP/2 over TLS", http.StatusBadRequest)
			return
		}
		io.WriteString(w, "hello "+r.URL.Path)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := Dial(ctx, "tcp", srv.Listener.Addr().String(), Config{
		Spec: chromeSpec,
		TLS:  tlsConfig(srv, "example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != ProtoH2 {
		t.Fatalf("ALPN = %q, want %q", got, ProtoH2)
	}

	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/spike", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 || string(body) != "hello /spike" {
		t.Fatalf("got %s %s %q", resp.Proto, resp.Status, body)
	}

	hello := rec.get()
	if hello == nil {
		t.Fatal("server recorded no ClientHello")
	}
	if !slices.Equal(hello.SupportedProtos, []string{ProtoH2, ProtoHTTP1}) {
		t.Errorf("ALPN offered = %q, want [h2 http/1.1]", hello.SupportedProtos)
	}
	if !slices.Contains(hello.SupportedCurves, tls.X25519MLKEM768) {
		t.Errorf("supported groups %v lack X25519MLKEM768", hello.SupportedCurves)
	}
	for _, ext := range []uint16{extCompressCertificate, extALPSNew} {
		if !slices.Contains(hello.Extensions, ext) {
			t.Errorf("ClientHello extensions %v lack %d", hello.Extensions, ext)
		}
	}
	if hello.ServerName != "example.com" {
		t.Errorf("SNI = %q, want example.com", hello.ServerName)
	}
}

// HTTP/1.1 is a valid outcome of Dial: the dispatcher sends it to the H1 engine.
func TestDialNegotiatesHTTP1(t *testing.T) {
	srv, _ := newTLSServer(t, []string{ProtoHTTP1}, http.NotFoundHandler())
	conn, err := Dial(context.Background(), "tcp", srv.Listener.Addr().String(), Config{
		Spec: chromeSpec,
		TLS:  tlsConfig(srv, "example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != ProtoHTTP1 {
		t.Fatalf("ALPN = %q, want %q", got, ProtoHTTP1)
	}
}

func TestDialUnsupportedALPN(t *testing.T) {
	srv, _ := newTLSServer(t, []string{"spdy/3"}, http.NotFoundHandler())
	var cc closeCounter
	_, err := Dial(context.Background(), "tcp", srv.Listener.Addr().String(), Config{
		Spec:        specWithALPN("spdy/3", ProtoHTTP1),
		TLS:         tlsConfig(srv, "example.com"),
		DialContext: cc.dial,
	})
	if !errors.Is(err, ErrALPN) {
		t.Fatalf("err = %v, want ErrALPN", err)
	}
	cc.check(t)
}

func TestDialCertificateNameMismatch(t *testing.T) {
	srv, _ := newTLSServer(t, []string{ProtoH2}, http.NotFoundHandler())
	var cc closeCounter
	_, err := Dial(context.Background(), "tcp", srv.Listener.Addr().String(), Config{
		Spec:        chromeSpec,
		TLS:         tlsConfig(srv, "wrong.example"),
		DialContext: cc.dial,
	})
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Fatalf("err = %v, want x509.HostnameError", err)
	}
	cc.check(t)
}

// A server that accepts TCP and never answers: the context ends the handshake.
// uTLS itself closes the connection when the context ends, so this checks the
// error and the time, not Dial's own Close (covered by the tests above).
func TestDialHandshakeDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var cc closeCounter
	start := time.Now()
	_, err = Dial(ctx, "tcp", ln.Addr().String(), Config{
		Spec:        chromeSpec,
		TLS:         &utls.Config{ServerName: "example.com"},
		DialContext: cc.dial,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Dial returned after %v", elapsed)
	}
	cc.check(t)
}

func TestDialSpecErrorOpensNoConnection(t *testing.T) {
	specErr := errors.New("no spec")
	var cc closeCounter
	_, err := Dial(context.Background(), "tcp", "127.0.0.1:1", Config{
		Spec:        func() (*utls.ClientHelloSpec, error) { return nil, specErr },
		TLS:         &utls.Config{ServerName: "example.com"},
		DialContext: cc.dial,
	})
	if !errors.Is(err, specErr) {
		t.Fatalf("err = %v, want the spec error", err)
	}
	if n := cc.dialed.Load(); n != 0 {
		t.Fatalf("dialed %d connections, want 0", n)
	}
}

// Each connection gets a new spec, so a generator can vary it per connection.
func TestDialCallsSpecPerConnection(t *testing.T) {
	srv, _ := newTLSServer(t, []string{ProtoH2}, http.NotFoundHandler())
	var calls atomic.Int32
	cfg := Config{
		Spec: func() (*utls.ClientHelloSpec, error) {
			calls.Add(1)
			return chromeSpec()
		},
		TLS: tlsConfig(srv, "example.com"),
	}
	for range 2 {
		conn, err := Dial(context.Background(), "tcp", srv.Listener.Addr().String(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("Spec called %d times for 2 connections", n)
	}
}

// The certificate is verified against Config.TLS.ServerName, the host of
// the URL. A spec that carries its own SNI name would replace it in uTLS, so
// a certificate for that name would be accepted for any URL: such a spec is
// refused before dialing.
func TestDialRefusesSpecServerName(t *testing.T) {
	srv, _ := newTLSServer(t, []string{ProtoH2}, http.NotFoundHandler())
	var cc closeCounter
	_, err := Dial(context.Background(), "tcp", srv.Listener.Addr().String(), Config{
		Spec: func() (*utls.ClientHelloSpec, error) {
			spec, err := chromeSpec()
			for _, ext := range spec.Extensions {
				if sni, ok := ext.(*utls.SNIExtension); ok {
					sni.ServerName = "example.com" // valid for the test certificate
				}
			}
			return spec, err
		},
		TLS:         tlsConfig(srv, "other.test"),
		DialContext: cc.dial,
	})
	if err == nil || !strings.Contains(err.Error(), "SNI") {
		t.Fatalf("err = %v, want the spec refused for its SNI name", err)
	}
	if n := cc.dialed.Load(); n != 0 {
		t.Fatalf("dialed %d connections, want 0", n)
	}
}

func TestDialNilSpecOpensNoConnection(t *testing.T) {
	srv, _ := newTLSServer(t, []string{ProtoH2}, http.NotFoundHandler())
	var cc closeCounter
	_, err := Dial(context.Background(), "tcp", srv.Listener.Addr().String(), Config{
		Spec:        func() (*utls.ClientHelloSpec, error) { return nil, nil },
		TLS:         &utls.Config{ServerName: "example.com"},
		DialContext: cc.dial,
	})
	if err == nil {
		t.Fatal("Dial accepted a nil spec")
	}
	if n := cc.dialed.Load(); n != 0 {
		t.Fatalf("dialed %d connections, want 0", n)
	}
}
