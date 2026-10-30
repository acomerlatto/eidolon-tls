package eidolon_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls"
)

// Origins on the same server and address never share a connection, as
// the pool key is the origin (no coalescing).
func TestIsolationOrigins(t *testing.T) {
	srv, _ := echLab(t)
	c := profileClient(t, srv, chrome)
	for _, u := range []string{"https://" + echSecret + "/", "https://other.test/", "https://" + echSecret + "/"} {
		if _, err := echGet(c, u); err != nil {
			t.Fatal(err)
		}
	}
	if n := srv.Accepted(); n != 2 {
		t.Errorf("%d connections, want one per origin", n)
	}
}

// Clients used at once keep their own profile, roots and ECH policy: a
// client without the roots of the server fails while the other succeeds,
// the ECH configuration of one is not offered by the other, and the
// ClientHello of each is its own.
func TestIsolationClients(t *testing.T) {
	srv, list := echLab(t)
	dial := eidolon.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Addr)
	})
	withECH, err := eidolon.New(chrome, dial, eidolon.WithRootCAs(srv.RootCAs), eidolon.WithECHConfig(echSecret, list))
	if err != nil {
		t.Fatal(err)
	}
	defer withECH.Close()
	chrome100 := func() (*utls.ClientHelloSpec, error) {
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_100)
		return &spec, err
	}
	other, err := eidolon.New(eidolon.WithClientHello(chrome100), dial, eidolon.WithRootCAs(srv.RootCAs))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	noRoots, err := eidolon.New(chrome, dial, eidolon.WithRootCAs(x509.NewCertPool()))
	if err != nil {
		t.Fatal(err)
	}
	defer noRoots.Close()

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if resp, err := echGet(withECH, "https://"+echSecret+"/"); err != nil || !resp.TLS.ECHAccepted {
				t.Errorf("client with ECH: %v", err)
			}
			if resp, err := echGet(other, "https://"+echSecret+"/"); err != nil || resp.TLS.ECHAccepted {
				t.Errorf("client without ECH configuration: %v", err)
			}
			if _, err := echGet(noRoots, "https://"+echSecret+"/"); !errors.Is(err, eidolon.ErrCertificate) {
				t.Errorf("client without the roots: %v, want ErrCertificate", err)
			}
		})
	}
	wg.Wait()
	// The client with ECH and the other one keep one connection each, with
	// the extensions of its own profile.
	var sets []string
	for range srv.Accepted() {
		c := srv.NextConn(t)
		if c.HandshakeErr == nil {
			exts := helloExtensions(t, c.ClientHello)
			slices.Sort(exts)
			sets = append(sets, fmt.Sprint(exts))
		}
	}
	if len(sets) != 2 || sets[0] == sets[1] {
		t.Errorf("served connections with extensions %q, want one per client, each its own", sets)
	}
}
