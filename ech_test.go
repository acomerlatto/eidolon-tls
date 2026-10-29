package eidolon_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

const (
	echSecret = "secret.test"
	echPublic = "public.test"
)

// echLab starts a lab server whose certificate covers echSecret,
// echPublic and other.test, and that accepts ECH with key. It returns the
// server and the ECHConfigList of key.
func echLab(t *testing.T) (*lab.Server, []byte) {
	t.Helper()
	list, key, err := lab.NewECHKey(1, echPublic)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := lab.NewCertificate(time.Hour, echSecret, echPublic, "other.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{
		Certificate: &cert,
		TLS:         func(c *tls.Config) { c.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{key} },
	})
	return srv, list
}

// echGet sends a GET to url and reads the body.
func echGet(c eidolon.HttpClient, url string) (*http.Response, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	return resp, err
}

// helloExtensions returns the extension types of a ClientHello handshake
// message.
func helloExtensions(t *testing.T, hello []byte) []uint16 {
	t.Helper()
	b := hello[4+2+32:]
	b = b[1+int(b[0]):]                   // session ID
	b = b[2+(int(b[0])<<8|int(b[1])):]    // cipher suites
	b = b[1+int(b[0]):]                   // compression methods
	b = b[2 : 2+(int(b[0])<<8|int(b[1]))] // extensions
	var types []uint16
	for len(b) >= 4 {
		types = append(types, uint16(b[0])<<8|uint16(b[1]))
		b = b[4+(int(b[2])<<8|int(b[3])):]
	}
	return types
}

// With the configuration of its origin, the request goes over a connection
// whose server accepted ECH: ClientHelloOuter names only the public name,
// and the server read the origin's name in ClientHelloInner. Chrome's
// profile builds ClientHelloInner with its own extensions.
func TestECHAccepted(t *testing.T) {
	srv, list := echLab(t)
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithECHConfig(echSecret, list))
	resp, err := echGet(c, "https://"+echSecret+"/")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.TLS.ECHAccepted {
		t.Error("Response.TLS.ECHAccepted is false")
	}
	conn := srv.NextConn(t)
	if !conn.State.ECHAccepted || conn.State.ServerName != echSecret {
		t.Errorf("server: ECH accepted %v, name %q", conn.State.ECHAccepted, conn.State.ServerName)
	}
	if !bytes.Contains(conn.ClientHello, []byte(echPublic)) || bytes.Contains(conn.ClientHello, []byte(echSecret)) {
		t.Error("ClientHelloOuter does not carry only the public name")
	}
}

// The configuration belongs to one origin: another host, or another port
// of the host, sends the GREASE ECH of the profile.
func TestECHOtherOrigins(t *testing.T) {
	srv, list := echLab(t)
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithECHConfig(echSecret, list))
	for _, url := range []string{"https://other.test/", "https://" + echSecret + ":8443/"} {
		resp, err := echGet(c, url)
		if err != nil {
			t.Fatal(err)
		}
		conn := srv.NextConn(t)
		if resp.TLS.ECHAccepted || conn.State.ECHAccepted {
			t.Errorf("%s: ECH accepted", url)
		}
		if !slices.Contains(helloExtensions(t, conn.ClientHello), 0xfe0d) {
			t.Errorf("%s: no GREASE ECH", url)
		}
		if bytes.Contains(conn.ClientHello, []byte(echPublic)) {
			t.Errorf("%s: ClientHello names the public name", url)
		}
	}
}

// ECHRequired fails, before any connection, a request to an origin
// without an ECH configuration, http:// included, and completes the
// others with ECH.
func TestECHRequired(t *testing.T) {
	srv, list := echLab(t)
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()),
		eidolon.WithECHConfig(echSecret, list), eidolon.WithECHMode(eidolon.ECHRequired))
	for _, url := range []string{"https://other.test/", "http://" + echSecret + "/", "https://" + echSecret + ":444/"} {
		if _, err := echGet(c, url); !errors.Is(err, eidolon.ErrECHRequired) {
			t.Errorf("%s: error %v, want ErrECHRequired", url, err)
		}
	}
	if n := srv.Accepted(); n != 0 {
		t.Fatalf("%d connections before the request with ECH", n)
	}
	resp, err := echGet(c, "https://"+echSecret+"/")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.TLS.ECHAccepted {
		t.Error("ECH not accepted")
	}
}

// ECHAuto is the default; ECHDisabled sends the GREASE ECH of the profile.
func TestECHModes(t *testing.T) {
	srv, _ := echLab(t)
	for _, mode := range []eidolon.ECHMode{eidolon.ECHAuto, eidolon.ECHDisabled} {
		c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithECHMode(mode))
		resp, err := echGet(c, "https://"+echSecret+"/")
		if err != nil {
			t.Fatal(err)
		}
		conn := srv.NextConn(t)
		if resp.TLS.ECHAccepted || !slices.Contains(helloExtensions(t, conn.ClientHello), 0xfe0d) {
			t.Errorf("mode %d: ECH accepted %v, extensions %d", mode, resp.TLS.ECHAccepted, helloExtensions(t, conn.ClientHello))
		}
	}
}

// A server that cannot decrypt ClientHelloInner rejects ECH: the request
// fails with ErrECHRejected, which keeps the utls.ECHRejectionError, and
// no HTTP byte is sent.
func TestECHRejected(t *testing.T) {
	srv, _ := echLab(t)
	other, _, err := lab.NewECHKey(2, echPublic)
	if err != nil {
		t.Fatal(err)
	}
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithECHConfig(echSecret, other))
	_, err = echGet(c, "https://"+echSecret+"/")
	var re *utls.ECHRejectionError
	if !errors.Is(err, eidolon.ErrECHRejected) || !errors.As(err, &re) || len(re.RetryConfigList) == 0 {
		t.Fatalf("error %v, want ErrECHRejected with retry configurations", err)
	}
	conn := srv.NextConn(t)
	<-conn.Done()
	if n := len(conn.Bytes()); n != 0 {
		t.Errorf("server read %d bytes after the handshake", n)
	}
}

// New refuses an ECH configuration it cannot use.
func TestECHConfigInvalid(t *testing.T) {
	good, _, err := lab.NewECHKey(1, echPublic)
	if err != nil {
		t.Fatal(err)
	}
	noECH := func() (*utls.ClientHelloSpec, error) {
		spec, err := chromeSpec()
		if err != nil {
			return nil, err
		}
		spec.Extensions = slices.DeleteFunc(spec.Extensions, func(e utls.TLSExtension) bool {
			_, ok := e.(utls.EncryptedClientHelloExtension)
			return ok
		})
		return spec, nil
	}
	unsupported := bytes.Clone(good)
	unsupported[2], unsupported[3] = 0xfe, 0x0c // an older version
	for _, tt := range []struct {
		name string
		opts []eidolon.Option
	}{
		{"IP address", []eidolon.Option{eidolon.WithECHConfig("127.0.0.1", good)}},
		{"bad authority", []eidolon.Option{eidolon.WithECHConfig("a b", good)}},
		{"empty list", []eidolon.Option{eidolon.WithECHConfig(echSecret, nil)}},
		{"set twice", []eidolon.Option{eidolon.WithECHConfig(echSecret, good), eidolon.WithECHConfig(echSecret+":443", good)}},
		{"malformed list", []eidolon.Option{eidolon.WithECHConfig(echSecret, good[:len(good)-1])}},
		{"no supported configuration", []eidolon.Option{eidolon.WithECHConfig(echSecret, unsupported)}},
		{"profile without ECH", []eidolon.Option{eidolon.WithClientHello(noECH), eidolon.WithECHConfig(echSecret, good)}},
		{"ECHDisabled", []eidolon.Option{eidolon.WithECHConfig(echSecret, good), eidolon.WithECHMode(eidolon.ECHDisabled)}},
		{"unknown mode", []eidolon.Option{eidolon.WithECHMode(3)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := append([]eidolon.Option{eidolon.WithClientHello(chromeSpec)}, tt.opts...)
			if _, err := eidolon.New(opts...); !errors.Is(err, eidolon.ErrConfig) {
				t.Errorf("New: %v, want ErrConfig", err)
			}
		})
	}
	// Each origin has its own configuration, and the list is copied.
	mine := bytes.Clone(good)
	opt := eidolon.WithECHConfig(echSecret, mine)
	clear(mine)
	if _, err := eidolon.New(eidolon.WithClientHello(chromeSpec), opt, eidolon.WithECHConfig(echSecret+":8443", good)); err != nil {
		t.Fatal(err)
	}
}
