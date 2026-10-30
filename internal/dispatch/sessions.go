package dispatch

import (
	"encoding/binary"
	"sync"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

const (
	// maxSessionKeys bounds the origins whose sessions are kept, as
	// Chrome's SSLClientSessionCache (Config::max_entries).
	maxSessionKeys = 1024
	// Chrome keeps a TLS 1.3 session for 2 days at most
	// (SSL_DEFAULT_SESSION_PSK_DHE_TIMEOUT), or less if the ticket
	// lifetime says so, and a chain of resumptions for 7 days from the
	// full handshake (SSL_DEFAULT_SESSION_AUTH_TIMEOUT); a TLS 1.2
	// session for 1 hour from the full handshake (SSL_CTX_set_timeout in
	// SSLClientSocketImpl's SSLContext).
	sessionTimeout13     = 48 * time.Hour
	sessionAuthTimeout13 = 7 * 24 * time.Hour
	sessionTimeout12     = time.Hour
)

// sessionCache holds the TLS sessions of a transport per origin, as
// Chrome's SSLClientSessionCache: the maxSessionKeys origins used last,
// two sessions each. A TLS 1.3 session is used once.
type sessionCache struct {
	now func() time.Time // time.Now; a variable for the tests

	mu   sync.Mutex
	keys *lru[*sessionPair]
}

// session is a session in the cache.
type session struct {
	cs      *utls.ClientSessionState
	tls13   bool      // used once
	auth    time.Time // of the full handshake it comes from
	expires time.Time
}

// sessionPair is the sessions of one origin, the most recent first
// (SSLClientSessionCache::Entry).
type sessionPair [2]*session

func newSessionCache() *sessionCache {
	return &sessionCache{now: time.Now, keys: newLRU[*sessionPair](maxSessionKeys)}
}

// push adds s in front: a TLS 1.3 session in front moves to second.
func (p *sessionPair) push(s *session) {
	if p[0] != nil && p[0].tls13 {
		p[1] = p[0]
	}
	p[0] = s
}

// pop returns the session in front, and takes it out if it is TLS 1.3.
func (p *sessionPair) pop() *session {
	s := p[0]
	if s != nil && s.tls13 {
		p[0], p[1] = p[1], nil
	}
	return s
}

// expired reports whether the pair is empty or its front has expired,
// when it goes as a whole. Chrome also drops an expired second session
// then; here it waits for its lookup, which finds it expired.
func (p *sessionPair) expired(now time.Time) bool {
	return p[0] == nil || !now.Before(p[0].expires)
}

// lookup takes a session of key, as SSLClientSessionCache::Lookup: nil
// when it has expired.
func (c *sessionCache) lookup(key string) *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.keys.get(key)
	if !ok {
		return nil
	}
	now := c.now()
	s := p.pop()
	if p.expired(now) {
		c.keys.remove(key)
	}
	if s == nil || !now.Before(s.expires) {
		return nil
	}
	return s
}

// insert adds s to the sessions of key.
func (c *sessionCache) insert(key string, s *session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.keys.get(key)
	if !ok {
		p = &sessionPair{}
		c.keys.put(key, p)
	}
	p.push(s)
}

// sessionsOf returns the session caches of the connections to origin, as
// tlsdial.Config.Sessions, or nil with noSessions.
func (t *Transport) sessionsOf(origin string) func() tlsdial.Sessions {
	if t.noSessions {
		return nil
	}
	t.mu.Lock()
	if t.sessions == nil {
		t.sessions = newSessionCache()
	}
	c := t.sessions
	t.mu.Unlock()
	return func() tlsdial.Sessions { return c.conn(origin) }
}

// conn returns the session cache of a new connection to key.
func (c *sessionCache) conn(key string) tlsdial.Sessions {
	return &connSessions{c: c, key: key}
}

// connSessions is the session cache of one connection (tlsdial.Sessions),
// used by one goroutine at a time: the dial, then the reads of the
// connection. The sessions put before the end of the handshake, in TLS
// 1.2, wait for it to learn whether it resumed.
type connSessions struct {
	c   *sessionCache
	key string

	offered *session
	done    bool
	auth    time.Time
	waiting []*utls.ClientSessionState
}

func (s *connSessions) Get(string) (*utls.ClientSessionState, bool) {
	s.offered = s.c.lookup(s.key)
	if s.offered == nil {
		return nil, false
	}
	return s.offered.cs, true
}

// Put keeps cs. A nil cs, which crypto/tls puts to forget the session of
// a failed handshake or one it cannot use, changes nothing: Chrome only
// lets sessions expire, and the TLS 1.3 one is already out.
func (s *connSessions) Put(_ string, cs *utls.ClientSessionState) {
	switch {
	case cs == nil:
	case !s.done:
		s.waiting = append(s.waiting, cs)
	default:
		s.insert(cs)
	}
}

// Unused puts back the TLS 1.3 session that Get took out.
func (s *connSessions) Unused() {
	if s.offered != nil && s.offered.tls13 {
		s.c.insert(s.key, s.offered)
	}
}

func (s *connSessions) Handshake(resumed bool) {
	s.done = true
	s.auth = s.c.now()
	if resumed {
		s.auth = s.offered.auth
	}
	for _, cs := range s.waiting {
		s.insert(cs)
	}
}

// insert adds cs, from the handshake of the connection, with its expiry.
func (s *connSessions) insert(cs *utls.ClientSessionState) {
	// The encoding of a SessionState starts with its version. The
	// session of a handshake has a state, which encodes.
	_, st, _ := cs.ResumptionState()
	b, _ := st.Bytes()
	tls13 := binary.BigEndian.Uint16(b) == utls.VersionTLS13
	expires := s.auth.Add(sessionTimeout12)
	if tls13 {
		expires = s.c.now().Add(sessionTimeout13)
		if a := s.auth.Add(sessionAuthTimeout13); a.Before(expires) {
			expires = a
		}
	}
	s.c.insert(s.key, &session{cs: cs, tls13: tls13, auth: s.auth, expires: expires})
}
