package tlsdial

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"
)

// uTLS-only exported fields, with no crypto/tls equivalent.
var utlsOnlyStateFields = []string{"PeerApplicationSettings"}

func exportedFields(t reflect.Type) []string {
	var names []string
	for f := range t.Fields() {
		if f.IsExported() {
			names = append(names, f.Name)
		}
	}
	slices.Sort(names)
	return names
}

// A new crypto/tls field after a Go upgrade, or a new uTLS field after a
// sync, fails here until the adapter handles it.
func TestConnectionStateFieldSets(t *testing.T) {
	std := exportedFields(reflect.TypeFor[tls.ConnectionState]())
	u := slices.DeleteFunc(exportedFields(reflect.TypeFor[utls.ConnectionState]()), func(name string) bool {
		return slices.Contains(utlsOnlyStateFields, name)
	})
	if !slices.Equal(std, u) {
		t.Fatalf("exported fields differ:\ncrypto/tls: %v\nuTLS:       %v", std, u)
	}
}

// fill sets v to a non-zero value of its type.
func fill(v reflect.Value, seed int) {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Uint16:
		v.SetUint(uint64(0x1000 + seed))
	case reflect.String:
		v.SetString("value")
	case reflect.Uint8:
		v.SetUint(uint64(seed))
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(s.Index(0), seed)
		v.Set(s)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
	default:
		panic("fill: unhandled kind " + v.Kind().String())
	}
}

// Every exported field reaches the crypto/tls value.
func TestConnectionStateCopiesEveryField(t *testing.T) {
	var src utls.ConnectionState
	sv := reflect.ValueOf(&src).Elem()
	for i := range sv.NumField() {
		if sv.Type().Field(i).IsExported() {
			fill(sv.Field(i), i)
		}
	}

	got := reflect.ValueOf(ConnectionState(src))
	for i := range got.NumField() {
		f := got.Type().Field(i)
		if !f.IsExported() {
			continue
		}
		g, s := got.Field(i), sv.FieldByName(f.Name)
		if g.Kind() == reflect.Uint16 { // CurveID is a distinct type in each package
			if g.Uint() != s.Uint() {
				t.Errorf("%s = %#x, want %#x", f.Name, g.Uint(), s.Uint())
			}
			continue
		}
		if !reflect.DeepEqual(g.Interface(), s.Interface()) {
			t.Errorf("%s not copied: got %v, want %v", f.Name, g.Interface(), s.Interface())
		}
	}
}

// handshakeAndRequest dials srv with spec, sends one HTTP/1.1 request and
// returns the client connection and the server's TLS state.
func handshakeAndRequest(t *testing.T, srv *httptest.Server, states <-chan tls.ConnectionState, spec func() (*utls.ClientHelloSpec, error)) (*utls.UConn, tls.ConnectionState) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, "tcp", srv.Listener.Addr().String(), Config{
		Spec: spec,
		TLS:  tlsConfig(srv, "example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return conn, <-states
}

func TestConnectionStateMatchesServer(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*tls.Config)
		wantVer    uint16
		wantHRR    bool
		wantUnique bool // tls-unique exists only up to TLS 1.2
	}{
		{name: "TLS 1.3", configure: func(*tls.Config) {}, wantVer: tls.VersionTLS13},
		{
			name: "TLS 1.3 with HelloRetryRequest",
			// Chrome sends key shares for X25519MLKEM768 and X25519 only.
			configure: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP256} },
			wantVer:   tls.VersionTLS13,
			wantHRR:   true,
		},
		{
			name:       "TLS 1.2",
			configure:  func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 },
			wantVer:    tls.VersionTLS12,
			wantUnique: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			states := make(chan tls.ConnectionState, 1)
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				states <- *r.TLS
			}))
			srv.Config.ErrorLog = log.New(io.Discard, "", 0)
			srv.TLS = &tls.Config{NextProtos: []string{ProtoHTTP1}}
			tt.configure(srv.TLS)
			srv.StartTLS()
			defer srv.Close()

			conn, server := handshakeAndRequest(t, srv, states, chromeSpec)
			got := ConnectionState(conn.ConnectionState())

			if got.Version != tt.wantVer || got.Version != server.Version {
				t.Errorf("Version = %#x, server %#x, want %#x", got.Version, server.Version, tt.wantVer)
			}
			if got.HelloRetryRequest != tt.wantHRR || server.HelloRetryRequest != tt.wantHRR {
				t.Errorf("HelloRetryRequest = %v, server %v, want %v", got.HelloRetryRequest, server.HelloRetryRequest, tt.wantHRR)
			}
			if got.CipherSuite != server.CipherSuite {
				t.Errorf("CipherSuite = %#x, server %#x", got.CipherSuite, server.CipherSuite)
			}
			if got.CurveID != server.CurveID {
				t.Errorf("CurveID = %v, server %v", got.CurveID, server.CurveID)
			}
			if got.NegotiatedProtocol != ProtoHTTP1 || server.NegotiatedProtocol != ProtoHTTP1 {
				t.Errorf("NegotiatedProtocol = %q, server %q", got.NegotiatedProtocol, server.NegotiatedProtocol)
			}
			if got.ServerName != "example.com" || server.ServerName != "example.com" {
				t.Errorf("ServerName = %q, server %q", got.ServerName, server.ServerName)
			}
			if !got.HandshakeComplete || got.DidResume || got.ECHAccepted {
				t.Errorf("HandshakeComplete %v, DidResume %v, ECHAccepted %v", got.HandshakeComplete, got.DidResume, got.ECHAccepted)
			}
			if (got.TLSUnique != nil) != tt.wantUnique || !slices.Equal(got.TLSUnique, server.TLSUnique) {
				t.Errorf("TLSUnique = %x, server %x", got.TLSUnique, server.TLSUnique)
			}

			cert := srv.Certificate()
			if len(got.PeerCertificates) == 0 || !got.PeerCertificates[0].Equal(cert) {
				t.Errorf("PeerCertificates do not start with the server certificate")
			}
			// The test certificate is self-signed, so the only chain is [cert].
			if len(got.VerifiedChains) != 1 || len(got.VerifiedChains[0]) != 1 || !got.VerifiedChains[0][0].Equal(cert) {
				t.Errorf("VerifiedChains = %d chains, want [[server certificate]]", len(got.VerifiedChains))
			}
		})
	}
}

// Documents the limits on keying material. The converted state never has it.
// The uTLS state has it only without renegotiation: like crypto/tls, uTLS
// refuses the exporter whenever Config.Renegotiation is not RenegotiateNever,
// even in TLS 1.3, and the Chrome spec's renegotiation_info extension sets
// RenegotiateOnceAsClient.
func TestConnectionStateExportKeyingMaterial(t *testing.T) {
	tests := []struct {
		name    string
		spec    func() (*utls.ClientHelloSpec, error)
		wantEKM bool
	}{
		{name: "Chrome spec", spec: chromeSpec},
		{name: "spec without renegotiation", spec: specWithALPN(ProtoHTTP1), wantEKM: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			states := make(chan tls.ConnectionState, 1)
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				states <- *r.TLS
			}))
			srv.TLS = &tls.Config{NextProtos: []string{ProtoHTTP1}}
			srv.StartTLS()
			defer srv.Close()

			conn, server := handshakeAndRequest(t, srv, states, tt.spec)
			if server.Version != tls.VersionTLS13 {
				t.Fatalf("Version = %#x, want TLS 1.3", server.Version)
			}
			const label = "EXPORTER-eidolon-test"
			want, err := server.ExportKeyingMaterial(label, nil, 32)
			if err != nil {
				t.Fatal(err)
			}
			us := conn.ConnectionState()
			got, err := us.ExportKeyingMaterial(label, nil, 32)
			if tt.wantEKM {
				if err != nil || !slices.Equal(got, want) {
					t.Fatalf("uTLS ExportKeyingMaterial = %x, %v; want %x", got, err, want)
				}
			} else if err == nil || !strings.Contains(err.Error(), "renegotiation") {
				t.Fatalf("uTLS ExportKeyingMaterial error = %v, want the renegotiation error", err)
			}

			converted := ConnectionState(us)
			defer func() {
				if recover() == nil {
					t.Error("ExportKeyingMaterial on the converted state did not panic")
				}
			}()
			converted.ExportKeyingMaterial(label, nil, 32)
		})
	}
}
