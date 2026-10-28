package eidolon_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// rsaCertificate returns a self-signed RSA certificate for the lab, as
// the suites with RSA authentication need.
func rsaCertificate(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: lab.ServerName},
		DNSNames:              []string{lab.ServerName},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// Over TLS 1.2 the client connects as Chrome, with a CBC suite or RSA key
// exchange over HTTP/1.1 too, and answers with the version and suite in
// Response.TLS; WithStrictTLS12 refuses those suites with ErrTLS12Policy,
// and accepts ECDHE with GCM. Over HTTP/2 they fail with
// ErrHTTP2InadequateSecurity, as in Chrome. Over TLS 1.3 (suite 0),
// WithStrictTLS12 changes nothing.
func TestTLS12(t *testing.T) {
	for _, tt := range []struct {
		name   string
		suite  uint16
		proto  string
		strict bool
		want   error
	}{
		{"GCM", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "h2", false, nil},
		{"GCM strict", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "h2", true, nil},
		{"CBC", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "http/1.1", false, nil},
		{"CBC strict", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "http/1.1", true, eidolon.ErrTLS12Policy},
		{"RSA", tls.TLS_RSA_WITH_AES_128_GCM_SHA256, "http/1.1", false, nil},
		{"CBC h2", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "h2", false, eidolon.ErrHTTP2InadequateSecurity},
		{"RSA h2", tls.TLS_RSA_WITH_AES_128_GCM_SHA256, "h2", false, eidolon.ErrHTTP2InadequateSecurity},
		{"TLS 1.3 strict", 0, "h2", true, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{tt.proto}, Certificate: rsaCertificate(t), TLS: func(c *tls.Config) {
				if tt.suite != 0 {
					c.MaxVersion = tls.VersionTLS12
					c.CipherSuites = []uint16{tt.suite}
				}
			}})
			var opts []eidolon.Option
			if tt.strict {
				opts = append(opts, eidolon.WithStrictTLS12())
			}
			c := newClient(t, srv, opts...)
			resp, err := c.Get("https://example.com/")
			if tt.want != nil {
				if !errors.Is(err, tt.want) {
					t.Fatalf("%v, want %v", err, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if tt.suite == 0 {
				if resp.TLS.Version != tls.VersionTLS13 {
					t.Errorf("version %#x", resp.TLS.Version)
				}
			} else if resp.TLS.Version != tls.VersionTLS12 || resp.TLS.CipherSuite != tt.suite {
				t.Errorf("version %#x, suite %#x", resp.TLS.Version, resp.TLS.CipherSuite)
			}
		})
	}
}

// The Chrome profile lets the server renegotiate as often as it asks, as
// Chrome does over HTTP/1.1.
func TestChrome156LinuxRenegotiation(t *testing.T) {
	spec, err := eidolon.Chrome156Linux().ClientHello()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range spec.Extensions {
		if ri, ok := e.(*utls.RenegotiationInfoExtension); ok {
			if ri.Renegotiation != utls.RenegotiateFreelyAsClient {
				t.Errorf("renegotiation %v", ri.Renegotiation)
			}
			return
		}
	}
	t.Error("no renegotiation_info")
}

// Over HTTP/2 with a suite HTTP/2 forbids, the client sends its preface
// and closes with GOAWAY INADEQUATE_SECURITY, without debug data and
// before any request, as Chrome. The server only reads: the HTTP/2 server
// of Go would refuse the connection first.
func TestHTTP2InadequateSecurity(t *testing.T) {
	srv := lab.Start(t, lab.Options{
		NextProtos:  []string{"h2"},
		Certificate: rsaCertificate(t),
		TLS: func(c *tls.Config) {
			c.MaxVersion = tls.VersionTLS12
			c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}
		},
		H2Conn: func(c net.Conn) { io.Copy(io.Discard, c); c.Close() },
	})
	c := newClient(t, srv)
	if _, err := c.Get("https://example.com/"); !errors.Is(err, eidolon.ErrHTTP2InadequateSecurity) {
		t.Fatalf("%v, want ErrHTTP2InadequateSecurity", err)
	}
	conn := srv.NextConn(t)
	var got []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		frames, err := conn.H2Frames()
		if err != nil {
			continue // the preface not read yet
		}
		got = got[:0]
		for _, f := range frames {
			got = append(got, fmt.Sprintf("%s %d %d", f.Type, f.ErrCode, len(f.Headers)))
		}
		if len(got) > 0 && strings.HasPrefix(got[len(got)-1], "GOAWAY") {
			break
		}
	}
	want := []string{"SETTINGS 0 0", "WINDOW_UPDATE 0 0", "GOAWAY 12 0"}
	if len(got) < 3 || !slices.Equal(got[:2], want[:2]) || got[len(got)-1] != want[2] || slices.ContainsFunc(got, func(s string) bool { return strings.HasPrefix(s, "HEADERS") }) {
		t.Errorf("frames %q, want %q", got, want)
	}
}
