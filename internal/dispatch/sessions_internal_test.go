package dispatch

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// putRecorder is a ClientSessionCache that records what is put.
type putRecorder struct{ got []*utls.ClientSessionState }

func (r *putRecorder) Get(string) (*utls.ClientSessionState, bool) { return nil, false }
func (r *putRecorder) Put(_ string, cs *utls.ClientSessionState) {
	if cs != nil {
		r.got = append(r.got, cs)
	}
}

// realSession returns a client session of version from a handshake with
// a crypto/tls server.
func realSession(t *testing.T, version uint16) *utls.ClientSessionState {
	t.Helper()
	cert, err := lab.NewCertificate(time.Hour, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	cc, sc := net.Pipe()
	defer cc.Close()
	go func() {
		defer sc.Close()
		s := tls.Server(sc, &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: version})
		if s.Handshake() == nil {
			s.Write([]byte{1})
		}
	}()
	rec := &putRecorder{}
	c := utls.Client(cc, &utls.Config{ServerName: "example.com", RootCAs: roots, ClientSessionCache: rec})
	if _, err := c.Read(make([]byte, 1)); err != nil { // after the TLS 1.3 ticket
		t.Fatal(err)
	}
	if len(rec.got) != 1 {
		t.Fatalf("%d sessions, want 1", len(rec.got))
	}
	return rec.got[0]
}

// clock is a time that the test moves.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// versionOf returns the TLS version of cs, with which its handshake ended.
func versionOf(cs *utls.ClientSessionState) uint16 {
	_, st, _ := cs.ResumptionState()
	b, _ := st.Bytes()
	return binary.BigEndian.Uint16(b) // the encoding starts with it
}

// fullHandshake puts cs as the session of a connection to key that did
// not resume, at the time of c.
func fullHandshake(c *sessionCache, key string, cs *utls.ClientSessionState) {
	s := c.conn(key)
	s.Handshake(versionOf(cs), false)
	s.Put(key, cs)
}

// offered returns the session the next connection to key offers.
func offered(c *sessionCache, key string) *utls.ClientSessionState {
	cs, _ := c.conn(key).Get(key)
	return cs
}

// A TLS 1.3 session is used once, and two are kept per origin, the most
// recent first; a TLS 1.2 session is used again and again, and a new one
// replaces it. As Chrome's SSLClientSessionCache::Entry.
func TestSessionPair(t *testing.T) {
	a, b, c := realSession(t, tls.VersionTLS13), realSession(t, tls.VersionTLS13), realSession(t, tls.VersionTLS13)
	cache := newSessionCache()
	for _, cs := range []*utls.ClientSessionState{a, b, c} {
		fullHandshake(cache, "o", cs)
	}
	for i, want := range []*utls.ClientSessionState{c, b, nil} {
		if got := offered(cache, "o"); got != want {
			t.Errorf("TLS 1.3 lookup %d: %p, want %p", i, got, want)
		}
	}

	x, y := realSession(t, tls.VersionTLS12), realSession(t, tls.VersionTLS12)
	fullHandshake(cache, "o", a)
	fullHandshake(cache, "o", x)
	for i := range 2 {
		if got := offered(cache, "o"); got != x {
			t.Errorf("TLS 1.2 lookup %d: %p, want %p", i, got, x)
		}
	}
	fullHandshake(cache, "o", y)
	if got := offered(cache, "o"); got != y {
		t.Errorf("after a new TLS 1.2 session: %p, want %p", got, y)
	}
	// A TLS 1.2 session in front is replaced; the TLS 1.3 one behind it
	// stays.
	fullHandshake(cache, "p", a)
	fullHandshake(cache, "p", x)
	fullHandshake(cache, "p", b)
	for i, want := range []*utls.ClientSessionState{b, a, nil} {
		if got := offered(cache, "p"); got != want {
			t.Errorf("lookup %d after TLS 1.2 then 1.3: %p, want %p", i, got, want)
		}
	}
}

// A TLS 1.3 session expires 48 hours after it came, and a chain of
// resumptions 7 days after its full handshake; a TLS 1.2 session 1 hour
// after its full handshake, even when the server renews its ticket.
func TestSessionExpiry(t *testing.T) {
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name    string
		version uint16
		// renew is how often the session is resumed and replaced, zero
		// for never.
		renew time.Duration
		life  time.Duration
	}{
		{"TLS 1.3", tls.VersionTLS13, 0, 48 * time.Hour},
		{"TLS 1.3 resumed", tls.VersionTLS13, 40 * time.Hour, 7 * 24 * time.Hour},
		{"TLS 1.2", tls.VersionTLS12, 0, time.Hour},
		{"TLS 1.2 renewed", tls.VersionTLS12, 40 * time.Minute, time.Hour},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// setup returns a cache at start plus tt.life minus before,
			// and the last session put.
			setup := func(before time.Duration) (*sessionCache, *utls.ClientSessionState) {
				last := realSession(t, tt.version)
				clk := &clock{start}
				cache := newSessionCache()
				cache.now = clk.now
				fullHandshake(cache, "o", last)
				for tt.renew > 0 && clk.t.Add(tt.renew).Before(start.Add(tt.life)) {
					clk.t = clk.t.Add(tt.renew)
					s := cache.conn("o")
					if cs, _ := s.Get("o"); cs != last {
						t.Fatalf("at %v: %p, want the last session", clk.t.Sub(start), cs)
					}
					s.Handshake(tt.version, true)
					last = realSession(t, tt.version)
					s.Put("o", last)
				}
				clk.t = start.Add(tt.life - before)
				return cache, last
			}
			if cache, last := setup(time.Second); offered(cache, "o") != last {
				t.Error("one second before its end, the session is not offered")
			}
			if cache, _ := setup(0); offered(cache, "o") != nil {
				t.Error("at its end, the session is offered")
			}
		})
	}
}

// A session put before the end of the handshake, as TLS 1.2 puts it,
// waits for it to learn whether it resumed; a nil one is not kept.
func TestSessionPutBeforeHandshake(t *testing.T) {
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	clk := &clock{start}
	cache := newSessionCache()
	cache.now = clk.now
	a, b := realSession(t, tls.VersionTLS12), realSession(t, tls.VersionTLS12)
	fullHandshake(cache, "o", a)
	clk.t = start.Add(40 * time.Minute)
	s := cache.conn("o")
	s.Get("o")
	s.Put("o", nil) // as crypto/tls forgets a session it cannot use
	s.Put("o", b)
	if got := offered(cache, "o"); got != a {
		t.Errorf("before the end of the handshake: %p, want the first session", got)
	}
	s.Handshake(tls.VersionTLS12, true)
	clk.t = start.Add(time.Hour)
	if got := offered(cache, "o"); got != nil {
		t.Errorf("an hour after the full handshake: %p, want none", got)
	}
}

// A connection whose dial failed gives its TLS 1.3 session back. A TLS 1.2
// session, which stayed, is not put again over a newer one.
func TestSessionUnused(t *testing.T) {
	a := realSession(t, tls.VersionTLS13)
	cache := newSessionCache()
	fullHandshake(cache, "o", a)
	s := cache.conn("o")
	s.Get("o")
	s.Unused()
	if got := offered(cache, "o"); got != a {
		t.Errorf("after a failed dial: %p, want the session", got)
	}

	x, y := realSession(t, tls.VersionTLS12), realSession(t, tls.VersionTLS12)
	fullHandshake(cache, "o", x)
	s = cache.conn("o")
	s.Get("o")
	fullHandshake(cache, "o", y)
	s.Unused()
	if got := offered(cache, "o"); got != y {
		t.Errorf("after a failed dial with TLS 1.2: %p, want the newer session", got)
	}
}

// The sessions of the 1024 origins used last are kept.
func TestSessionKeys(t *testing.T) {
	a := realSession(t, tls.VersionTLS12)
	cache := newSessionCache()
	for i := range 1024 {
		fullHandshake(cache, fmt.Sprint(i), a)
	}
	if offered(cache, "0") != a {
		t.Fatal("of 1024 origins, the first is dropped")
	}
	fullHandshake(cache, "new", a)
	if offered(cache, "1") != nil {
		t.Error("the origin used least recently is kept")
	}
	if offered(cache, "0") != a || offered(cache, "2") != a || offered(cache, "new") != a {
		t.Error("an origin used recently is dropped")
	}
}

// When the session in front has expired, the origin loses both: here the
// TLS 1.3 session behind an expired TLS 1.2 one.
func TestSessionFrontExpired(t *testing.T) {
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	clk := &clock{start}
	cache := newSessionCache()
	cache.now = clk.now
	a, b, x := realSession(t, tls.VersionTLS13), realSession(t, tls.VersionTLS13), realSession(t, tls.VersionTLS12)
	fullHandshake(cache, "o", a)
	fullHandshake(cache, "o", x)
	clk.t = start.Add(sessionTimeout12)
	if got := offered(cache, "o"); got != nil {
		t.Fatalf("expired TLS 1.2 session offered: %p", got)
	}
	fullHandshake(cache, "o", b)
	for i, want := range []*utls.ClientSessionState{b, nil} {
		if got := offered(cache, "o"); got != want {
			t.Errorf("lookup %d: %p, want %p", i, got, want)
		}
	}
}

// A handshake that did not resume the session offered, which the server
// declined, starts a new chain of resumptions.
func TestSessionDeclined(t *testing.T) {
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	clk := &clock{start}
	cache := newSessionCache()
	cache.now = clk.now
	last := realSession(t, tls.VersionTLS13)
	fullHandshake(cache, "o", last)
	for i := 1; i <= 4; i++ {
		clk.t = start.Add(time.Duration(i) * 40 * time.Hour)
		s := cache.conn("o")
		s.Get("o")
		s.Handshake(tls.VersionTLS13, i < 4) // the fourth is declined
		last = realSession(t, tls.VersionTLS13)
		s.Put("o", last)
	}
	// 200 hours after the first, 40 after the last full handshake.
	clk.t = start.Add(200 * time.Hour)
	if got := offered(cache, "o"); got != last {
		t.Errorf("%p, want the session of the new full handshake", got)
	}
}
