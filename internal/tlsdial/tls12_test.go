package tlsdial

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	utls "github.com/acomerlatto/utls"
)

// tls12Server starts an HTTPS server, with an RSA certificate, that only
// speaks TLS 1.2 with suites (nil for the defaults) and offers nextProtos.
func tls12Server(t *testing.T, suites []uint16, nextProtos []string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: suites, NextProtos: nextProtos}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// The Chrome spec connects over TLS 1.2 with whatever suite it offers that
// the server picks, as Chrome; StrictTLS12 refuses the suites without
// ECDHE and AEAD, after the handshake, and closes the connection.
func TestTLS12Policy(t *testing.T) {
	for _, tt := range []struct {
		name   string
		suites []uint16
		strict bool // StrictTLS12 accepts it
	}{
		{"ECDHE GCM", []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, true},
		{"ECDHE ChaCha20", []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}, true},
		{"ECDHE CBC", []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}, false},
		{"RSA GCM", []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}, false},
		{"RSA CBC", []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := tls12Server(t, tt.suites, []string{ProtoHTTP1})
			for _, strict := range []bool{false, true} {
				var cc closeCounter
				conn, err := Dial(context.Background(), "tcp", srv.Listener.Addr().String(), Config{
					Spec: chromeSpec, TLS: tlsConfig(srv, "example.com"), DialContext: cc.dial, StrictTLS12: strict,
				})
				if !strict || tt.strict {
					if err != nil {
						t.Fatalf("strict %v: %v", strict, err)
					}
					st := conn.ConnectionState()
					if st.Version != utls.VersionTLS12 || st.CipherSuite != tt.suites[0] {
						t.Errorf("strict %v: version %#x, suite %#x", strict, st.Version, st.CipherSuite)
					}
					conn.Close()
					continue
				}
				if !errors.Is(err, ErrTLS12Policy) || conn != nil {
					t.Fatalf("strict: %v, %v; want ErrTLS12Policy", conn, err)
				}
				cc.check(t)
			}
		})
	}
}

// Without extended master secret or secure renegotiation, StrictTLS12
// refuses the server; a Go server always has both.
func TestStrictTLS12ServerHello(t *testing.T) {
	const suite = utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	for _, tt := range []struct {
		sh   *utls.PubServerHelloMsg
		want string
	}{
		{&utls.PubServerHelloMsg{ExtendedMasterSecret: true, SecureRenegotiationSupported: true}, ""},
		{&utls.PubServerHelloMsg{SecureRenegotiationSupported: true}, "extended master secret"},
		{&utls.PubServerHelloMsg{ExtendedMasterSecret: true}, "secure renegotiation"},
		{nil, "extended master secret"},
	} {
		err := strictTLS12(suite, tt.sh)
		if tt.want == "" && err != nil || tt.want != "" && (!errors.Is(err, ErrTLS12Policy) || !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%+v: %v, want %q", tt.sh, err, tt.want)
		}
	}
}

// The server may renegotiate over HTTP/1.1, as the spec says, and never
// over HTTP/2: keying material, which uTLS refuses while renegotiation is
// allowed, is there only over HTTP/2.
func TestRenegotiationByProtocol(t *testing.T) {
	for _, proto := range []string{ProtoH2, ProtoHTTP1} {
		t.Run(proto, func(t *testing.T) {
			srv := tls12Server(t, nil, []string{proto})
			conn, err := Dial(context.Background(), "tcp", srv.Listener.Addr().String(), Config{
				Spec: chromeSpec, TLS: tlsConfig(srv, "example.com"),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			st := conn.ConnectionState()
			if st.Version != utls.VersionTLS12 {
				t.Fatalf("version %#x", st.Version)
			}
			_, err = st.ExportKeyingMaterial("EXPORTER-eidolon-test", nil, 32)
			if renegotiates := err != nil && strings.Contains(err.Error(), "renegotiation"); renegotiates != (proto == ProtoHTTP1) {
				t.Errorf("keying material error %v", err)
			}
		})
	}
}
