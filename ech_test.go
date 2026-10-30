package eidolon_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
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

// echRejectingLab starts a lab server with a certificate for names that
// cannot decrypt the ECH configuration the client gets, the list it
// returns, and answers with keys as its retry configurations.
func echRejectingLab(t *testing.T, names []string, keys ...tls.EncryptedClientHelloKey) (*lab.Server, []byte) {
	t.Helper()
	stale, _, err := lab.NewECHKey(9, echPublic)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := lab.NewCertificate(time.Hour, names...)
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{
		Certificate: &cert,
		TLS:         func(c *tls.Config) { c.EncryptedClientHelloKeys = keys },
	})
	return srv, stale
}

// echKey returns a new ECH key for echPublic.
func echKey(t *testing.T) tls.EncryptedClientHelloKey {
	t.Helper()
	_, key, err := lab.NewECHKey(1, echPublic)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// checkRejected checks that conn, a connection whose server rejected ECH,
// carried no HTTP byte. The server completes its handshake before the
// client's ech_required alert.
func checkRejected(t *testing.T, conn *lab.Conn) {
	t.Helper()
	<-conn.Done()
	if conn.State.ECHAccepted {
		t.Error("the rejected connection has ECH accepted")
	}
	if n := len(conn.Bytes()); n != 0 {
		t.Errorf("server read %d bytes after the rejection", n)
	}
}

// A server that cannot decrypt ClientHelloInner rejects ECH and sends its
// retry configurations, authenticated by a certificate for the public
// name: the request goes over one new connection that offers ECH with
// them, in both modes.
func TestECHRetryConfigs(t *testing.T) {
	for _, mode := range []eidolon.ECHMode{eidolon.ECHAuto, eidolon.ECHRequired} {
		key := echKey(t)
		key.SendAsRetry = true
		srv, stale := echRejectingLab(t, []string{echSecret, echPublic}, key)
		c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()),
			eidolon.WithECHConfig(echSecret, stale), eidolon.WithECHMode(mode))
		resp, err := echGet(c, "https://"+echSecret+"/")
		if err != nil {
			t.Fatalf("mode %d: %v", mode, err)
		}
		checkRejected(t, srv.NextConn(t))
		conn := srv.NextConn(t)
		if !resp.TLS.ECHAccepted || !conn.State.ECHAccepted || conn.State.ServerName != echSecret {
			t.Errorf("mode %d: retry with ECH accepted %v, server name %q", mode, resp.TLS.ECHAccepted, conn.State.ServerName)
		}
	}
}

// Without usable retry configurations, ECHAuto sends the request over one
// new connection with the GREASE ECH of the profile, as Chrome, and
// ECHRequired fails with ErrECHRequired and ErrECHRejected.
func TestECHRetryWithoutConfigs(t *testing.T) {
	unsupported := echKey(t)
	unsupported.SendAsRetry = true
	unsupported.Config = bytes.Clone(unsupported.Config)
	unsupported.Config[0], unsupported.Config[1] = 0xfe, 0x0c // an older version
	for _, tt := range []struct {
		name string
		keys []tls.EncryptedClientHelloKey
	}{
		{"none sent", nil},
		{"none supported", []tls.EncryptedClientHelloKey{unsupported}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, stale := echRejectingLab(t, []string{echSecret, echPublic}, tt.keys...)
			c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithECHConfig(echSecret, stale))
			resp, err := echGet(c, "https://"+echSecret+"/")
			if err != nil {
				t.Fatal(err)
			}
			checkRejected(t, srv.NextConn(t))
			conn := srv.NextConn(t)
			if resp.TLS.ECHAccepted || conn.State.ServerName != echSecret || !slices.Contains(helloExtensions(t, conn.ClientHello), 0xfe0d) {
				t.Errorf("retry: ECH accepted %v, server name %q, extensions %d", resp.TLS.ECHAccepted, conn.State.ServerName, helloExtensions(t, conn.ClientHello))
			}

			srv, stale = echRejectingLab(t, []string{echSecret, echPublic}, tt.keys...)
			c = profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()),
				eidolon.WithECHConfig(echSecret, stale), eidolon.WithECHMode(eidolon.ECHRequired))
			_, err = echGet(c, "https://"+echSecret+"/")
			if !errors.Is(err, eidolon.ErrECHRequired) || !errors.Is(err, eidolon.ErrECHRejected) {
				t.Fatalf("ECHRequired: %v, want ErrECHRequired and ErrECHRejected", err)
			}
			checkRejected(t, srv.NextConn(t))
			if n := srv.Accepted(); n != 1 {
				t.Errorf("ECHRequired: %d connections, want 1", n)
			}
		})
	}
}

// The retry is made once: a server that rejects it too fails the request
// with ErrECHRejected, which keeps the utls.ECHRejectionError, and no HTTP
// byte is sent.
func TestECHRejectedTwice(t *testing.T) {
	key := echKey(t)
	key.PrivateKey = echKey(t).PrivateKey // the server cannot decrypt its own configuration
	key.SendAsRetry = true
	srv, stale := echRejectingLab(t, []string{echSecret, echPublic}, key)
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithECHConfig(echSecret, stale))
	_, err := echGet(c, "https://"+echSecret+"/")
	var re *utls.ECHRejectionError
	if !errors.Is(err, eidolon.ErrECHRejected) || !errors.As(err, &re) || !bytes.Contains(re.RetryConfigList, key.Config) {
		t.Fatalf("error %v, want ErrECHRejected with the retry configurations", err)
	}
	checkRejected(t, srv.NextConn(t))
	checkRejected(t, srv.NextConn(t))
	if n := srv.Accepted(); n != 2 {
		t.Errorf("%d connections, want 2", n)
	}
}

// A TLS 1.2 server cannot accept ECH: as BoringSSL, the handshake is a
// rejection without retry configurations, authenticated for the public
// name. ECHAuto sends the request over a new connection with the GREASE
// ECH of the profile; ECHRequired fails.
func TestECHRejectedByTLS12(t *testing.T) {
	for _, mode := range []eidolon.ECHMode{eidolon.ECHAuto, eidolon.ECHRequired} {
		cert, err := lab.NewCertificate(time.Hour, echSecret, echPublic)
		if err != nil {
			t.Fatal(err)
		}
		srv := lab.Start(t, lab.Options{
			Certificate: &cert,
			TLS:         func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 },
		})
		list, _, err := lab.NewECHKey(1, echPublic)
		if err != nil {
			t.Fatal(err)
		}
		c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()),
			eidolon.WithECHConfig(echSecret, list), eidolon.WithECHMode(mode))
		resp, err := echGet(c, "https://"+echSecret+"/")
		checkRejected(t, srv.NextConn(t))
		if mode == eidolon.ECHRequired {
			if !errors.Is(err, eidolon.ErrECHRequired) || !errors.Is(err, eidolon.ErrECHRejected) {
				t.Fatalf("ECHRequired: %v, want ErrECHRequired and ErrECHRejected", err)
			}
			if n := srv.Accepted(); n != 1 {
				t.Errorf("ECHRequired: %d connections, want 1", n)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		conn := srv.NextConn(t)
		if resp.TLS.Version != tls.VersionTLS12 || resp.TLS.ECHAccepted || conn.State.ServerName != echSecret ||
			!slices.Contains(helloExtensions(t, conn.ClientHello), 0xfe0d) {
			t.Errorf("retry: version %x, ECH accepted %v, server name %q", resp.TLS.Version, resp.TLS.ECHAccepted, conn.State.ServerName)
		}
	}
}

// A rejection is authenticated for the public name of the configuration:
// a certificate for the origin's name alone fails the request with
// ErrCertificate, without a retry.
func TestECHRejectionCertificate(t *testing.T) {
	key := echKey(t)
	key.SendAsRetry = true
	srv, stale := echRejectingLab(t, []string{echSecret}, key)
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithECHConfig(echSecret, stale))
	if _, err := echGet(c, "https://"+echSecret+"/"); !errors.Is(err, eidolon.ErrCertificate) {
		t.Fatalf("error %v, want ErrCertificate", err)
	}
	checkRejected(t, srv.NextConn(t))
	if n := srv.Accepted(); n != 1 {
		t.Errorf("%d connections, want 1", n)
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
	// without returns the Chrome profile changed by f.
	without := func(f func(spec *utls.ClientHelloSpec)) func() (*utls.ClientHelloSpec, error) {
		return func() (*utls.ClientHelloSpec, error) {
			spec, err := chromeSpec()
			if err != nil {
				return nil, err
			}
			f(spec)
			return spec, nil
		}
	}
	noTLS13 := without(func(spec *utls.ClientHelloSpec) {
		for _, e := range spec.Extensions {
			if sv, ok := e.(*utls.SupportedVersionsExtension); ok {
				sv.Versions = []uint16{utls.GREASE_PLACEHOLDER, utls.VersionTLS12}
			}
		}
	})
	noSNI := without(func(spec *utls.ClientHelloSpec) {
		spec.Extensions = slices.DeleteFunc(spec.Extensions, func(e utls.TLSExtension) bool {
			_, ok := e.(*utls.SNIExtension)
			return ok
		})
	})
	ipv4, _, err := lab.NewECHKey(1, "127.1")
	if err != nil {
		t.Fatal(err)
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
		{"IPv4 public name", []eidolon.Option{eidolon.WithECHConfig(echSecret, ipv4)}},
		{"profile without ECH", []eidolon.Option{eidolon.WithClientHello(noECH), eidolon.WithECHConfig(echSecret, good)}},
		{"profile without TLS 1.3", []eidolon.Option{eidolon.WithClientHello(noTLS13), eidolon.WithECHConfig(echSecret, good)}},
		{"profile without server_name", []eidolon.Option{eidolon.WithClientHello(noSNI), eidolon.WithECHConfig(echSecret, good)}},
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
	// The error of an invalid authority says why.
	if _, err := eidolon.New(eidolon.WithClientHello(chromeSpec), eidolon.WithECHConfig(echSecret+":99999", good)); err == nil || !strings.Contains(err.Error(), `invalid port "99999"`) {
		t.Errorf("New with port 99999: %v, want the invalid port", err)
	}
	// With several invalid configurations, the error names the first
	// origin in order, each time.
	for range 20 {
		_, err := eidolon.New(eidolon.WithClientHello(chromeSpec), eidolon.WithECHConfig("b.test", unsupported),
			eidolon.WithECHConfig("a.test", unsupported), eidolon.WithECHConfig("c.test", unsupported))
		if err == nil || !strings.Contains(err.Error(), "https://a.test") {
			t.Fatalf("New: %v, want the origin https://a.test", err)
		}
	}
	// Those profiles are valid without ECH.
	for _, spec := range []func() (*utls.ClientHelloSpec, error){noTLS13, noSNI} {
		if _, err := eidolon.New(eidolon.WithClientHello(spec)); err != nil {
			t.Errorf("New without ECH: %v", err)
		}
	}
	// Each origin has its own configuration, and the list is copied.
	mine := bytes.Clone(good)
	opt := eidolon.WithECHConfig(echSecret, mine)
	clear(mine)
	if _, err := eidolon.New(eidolon.WithClientHello(chromeSpec), opt, eidolon.WithECHConfig(echSecret+":8443", good)); err != nil {
		t.Fatal(err)
	}
}

// helloExtension returns the body of extension typ of a ClientHello
// handshake message, and whether it is there.
func helloExtension(t *testing.T, hello []byte, typ uint16) ([]byte, bool) {
	t.Helper()
	b := hello[4+2+32:]
	b = b[1+int(b[0]):]
	b = b[2+(int(b[0])<<8|int(b[1])):]
	b = b[1+int(b[0]):]
	b = b[2 : 2+(int(b[0])<<8|int(b[1]))]
	for len(b) >= 4 {
		n := int(b[2])<<8 | int(b[3])
		if uint16(b[0])<<8|uint16(b[1]) == typ {
			return b[4 : 4+n], true
		}
		b = b[4+n:]
	}
	return nil, false
}

// The ClientHelloOuter of the Chrome profile has the extensions of its
// ClientHello without ECH, as BoringSSL aligns them, and carries no ticket
// or PSK, even on a connection that resumes: the session goes in
// ClientHelloInner only. Its encrypted_client_hello is of type outer, with
// the configuration's suite and id, and a payload of a padded
// ClientHelloInner.
func TestECHOuter(t *testing.T) {
	srv, list := echLab(t)
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithECHConfig(echSecret, list))
	var hellos [][]byte
	for i, url := range []string{"https://" + echSecret + "/", "https://" + echSecret + "/", "https://other.test/"} {
		resp, err := echGet(c, url)
		if err != nil {
			t.Fatal(err)
		}
		hellos = append(hellos, srv.NextConn(t).ClientHello)
		c.CloseIdleConnections()
		if resp.TLS.DidResume != (i == 1) {
			t.Errorf("connection %d to %s: resumed %v", i, url, resp.TLS.DidResume)
		}
	}
	// sorted returns the extension types of hello in order, every GREASE
	// value as 0x0a0a.
	sorted := func(hello []byte) []uint16 {
		types := helloExtensions(t, hello)
		for i, typ := range types {
			if typ&0x0f0f == 0x0a0a && typ>>8 == typ&0xff {
				types[i] = 0x0a0a
			}
		}
		slices.Sort(types)
		return types
	}
	plain := sorted(hellos[2])
	for i, hello := range hellos[:2] {
		if got := sorted(hello); !slices.Equal(got, plain) {
			t.Errorf("connection %d: outer extensions %d, without ECH %d", i, got, plain)
		}
		if ticket, _ := helloExtension(t, hello, 35); len(ticket) != 0 {
			t.Errorf("connection %d: session ticket in the outer", i)
		}
		if _, ok := helloExtension(t, hello, 41); ok {
			t.Errorf("connection %d: pre_shared_key in the outer", i)
		}
		ech, _ := helloExtension(t, hello, 0xfe0d)
		// type, KDF, AEAD, config id, enc (32 bytes), payload
		if len(ech) < 1+2+2+1+2+32+2 || ech[0] != 0 || !bytes.Equal(ech[1:6], []byte{0, 1, 0, 1, 1}) ||
			int(ech[6])<<8|int(ech[7]) != 32 {
			t.Fatalf("connection %d: encrypted_client_hello %x", i, ech[:min(len(ech), 8)])
		}
		payload := ech[8+32+2:]
		if n := int(ech[40])<<8 | int(ech[41]); n != len(payload) || (n-16)%32 != 0 {
			t.Errorf("connection %d: payload of %d bytes, not a padded ClientHelloInner", i, len(payload))
		}
	}
}

// The ClientHelloInner of the Chrome profile, read by crypto/tls, has the
// cipher suites, versions and extensions of Chrome: GREASE and TLS 1.3
// suites, TLS 1.3 alone, and no TLS 1.2 extension.
func TestECHInnerChrome156(t *testing.T) {
	list, key, err := lab.NewECHKey(1, echPublic)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := lab.NewCertificate(time.Hour, echSecret, echPublic)
	if err != nil {
		t.Fatal(err)
	}
	inner := make(chan *tls.ClientHelloInfo, 1)
	srv := lab.Start(t, lab.Options{
		Certificate: &cert,
		TLS: func(c *tls.Config) {
			c.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{key}
			c.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				inner <- chi
				return nil, nil
			}
		},
	})
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithECHConfig(echSecret, list))
	if _, err := echGet(c, "https://"+echSecret+"/"); err != nil {
		t.Fatal(err)
	}
	chi := <-inner
	if chi.ServerName != echSecret {
		t.Errorf("inner name %q", chi.ServerName)
	}
	if len(chi.CipherSuites) != 4 || !slices.Equal(chi.CipherSuites[1:], []uint16{0x1301, 0x1302, 0x1303}) {
		t.Errorf("inner cipher suites %x", chi.CipherSuites)
	}
	if len(chi.SupportedVersions) != 2 || chi.SupportedVersions[1] != tls.VersionTLS13 {
		t.Errorf("inner versions %x", chi.SupportedVersions)
	}
	for _, typ := range chi.Extensions {
		switch typ {
		case 23, 0xff01, 35, 11, 41: // EMS, renegotiation_info, session_ticket, ec_point_formats, PSK
			t.Errorf("inner has extension %d", typ)
		}
	}
	outer := helloExtensions(t, srv.NextConn(t).ClientHello)
	if want := len(outer) - 4; len(chi.Extensions) != want {
		t.Errorf("inner has %d extensions, want %d: %d", len(chi.Extensions), want, chi.Extensions)
	}
}
