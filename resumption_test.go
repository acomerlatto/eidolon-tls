package eidolon_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

const extPreSharedKey = 41

// getNew sends a GET to url, reads the body and closes the idle connections,
// so that the next request opens a new one.
func getNew(t *testing.T, c eidolon.HttpClient, url string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	c.CloseIdleConnections()
}

// resumed returns whether each of the next n connections of srv resumed a
// session, and fails t if a ClientHello that resumes in TLS 1.3 does not
// end with pre_shared_key, or one that does not has it.
func resumed(t *testing.T, srv *lab.Server, n int) []bool {
	t.Helper()
	var got []bool
	for range n {
		c := srv.NextConn(t)
		if c.HandshakeErr != nil {
			t.Fatal(c.HandshakeErr)
		}
		exts := helloExtensions(t, c.ClientHello)
		psk := slices.Contains(exts, extPreSharedKey)
		if psk && exts[len(exts)-1] != extPreSharedKey {
			t.Errorf("pre_shared_key is not the last extension: %v", exts)
		}
		if c.State.Version == tls.VersionTLS13 && psk != c.State.DidResume {
			t.Errorf("pre_shared_key %v, resumed %v", psk, c.State.DidResume)
		}
		got = append(got, c.State.DidResume)
	}
	return got
}

// As Chrome, the connections after the first to an origin resume the
// session the server gave, in TLS 1.3 with pre_shared_key last, and in
// TLS 1.2 with the ticket; over HTTP/2 and HTTP/1.1.
func TestResumption(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		for _, proto := range []string{"h2", "http/1.1"} {
			t.Run(tls.VersionName(version)+"/"+proto, func(t *testing.T) {
				srv := lab.Start(t, lab.Options{NextProtos: []string{proto}, TLS: func(c *tls.Config) { c.MaxVersion = version }})
				c := profileClient(t, srv, chrome)
				for range 3 {
					getNew(t, c, "https://example.com/")
				}
				if got := resumed(t, srv, 3); !slices.Equal(got, []bool{false, true, true}) {
					t.Errorf("resumed %v, want [false true true]", got)
				}
			})
		}
	}
}

// The sessions are kept per origin and per client: a session of one
// origin is not offered to another on the same server, nor a session of
// one client by another.
func TestResumptionIsolation(t *testing.T) {
	cert, err := lab.NewCertificate(time.Hour, "a.test", "b.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{Certificate: &cert})
	c := profileClient(t, srv, chrome)
	getNew(t, c, "https://a.test/")
	getNew(t, c, "https://b.test/")
	getNew(t, profileClient(t, srv, chrome), "https://a.test/")
	getNew(t, c, "https://a.test/")
	if got := resumed(t, srv, 4); !slices.Equal(got, []bool{false, false, false, true}) {
		t.Errorf("resumed %v, want [false false false true]", got)
	}
}

// With WithNewConnectionPerRequest, as with a rotating proxy, no session
// is resumed: each request looks like a new browser.
func TestNoResumptionNewConnPerRequest(t *testing.T) {
	srv := lab.Start(t, lab.Options{})
	c := profileClient(t, srv, chrome, eidolon.WithNewConnectionPerRequest())
	for range 3 {
		getNew(t, c, "https://example.com/")
	}
	if got := resumed(t, srv, 3); slices.Contains(got, true) {
		t.Errorf("resumed %v, want none", got)
	}
}

// A connection with ECH neither resumes nor keeps a session, until the
// session goes in ClientHelloInner; one without it, with GREASE ECH,
// resumes.
func TestNoResumptionECH(t *testing.T) {
	srv, list := echLab(t)
	c := profileClient(t, srv, chrome, eidolon.WithECHConfig(echSecret, list))
	for range 2 {
		getNew(t, c, "https://"+echSecret+"/")
	}
	getNew(t, c, "https://other.test/")
	getNew(t, c, "https://other.test/")
	if got := resumed(t, srv, 4); !slices.Equal(got, []bool{false, false, false, true}) {
		t.Errorf("resumed %v, want [false false false true]", got)
	}
}

// A TLS 1.3 session is used once: of two connections opened together
// after a server that gave one ticket, only one resumes.
func TestResumptionSingleUse(t *testing.T) {
	var arrived sync.WaitGroup
	arrived.Add(2)
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/both" {
			arrived.Done()
			arrived.Wait()
		}
	})})
	// The two connections take their sessions before either dials, so
	// the ticket of the one that resumes comes too late for the other.
	var dials atomic.Int32
	var together sync.WaitGroup
	together.Add(2)
	c := profileClient(t, srv, chrome, eidolon.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
		if dials.Add(1) > 1 {
			together.Done()
			together.Wait()
		}
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Addr)
	}))
	getNew(t, c, "https://example.com/")
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			resp, err := c.Get("https://example.com/both")
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		})
	}
	wg.Wait()
	got := resumed(t, srv, 3)
	if n := len(slices.DeleteFunc(got[1:], func(r bool) bool { return !r })); got[0] || n != 1 {
		t.Errorf("resumed %v, want the first not and one of the others", got)
	}
}
