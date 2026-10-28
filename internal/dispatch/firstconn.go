package dispatch

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/target"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// sharedDialTimeout bounds a dial shared by the requests waiting for the
// first connection of a key. The dial belongs to the Transport, not to the
// request that started it, so it has its own deadline; each waiter stops at
// its own context.
const sharedDialTimeout = 30 * time.Second

// dialCall is a dial shared by the requests of one key while its protocol
// is unknown or h2 without a usable connection.
type dialCall struct {
	done chan struct{}
	// After done: an http/1.1 connection for one waiter, nil when the dial
	// failed or put an h2 connection in the pool.
	conn *utls.UConn
	err  error

	// Guarded by Transport.mu.
	waiters int
	taken   bool
}

// connFor returns an HTTP/1.1 connection for a request of key, or nil
// when an h2 connection was put in the pool. With fresh, an HTTP/1.1
// connection is a new one (h1Acquire).
//
// An origin learned as http/1.1 takes its connection from the HTTP/1.1
// pool, which dials in parallel up to the limit. Otherwise the requests
// wait for one shared dial, as Chrome does: with h2 they all multiplex on
// it; with http/1.1 one waiter takes the connection and the others go to
// the HTTP/1.1 pool.
func (t *Transport) connFor(ctx context.Context, tgt target.Target, key string, fresh bool) (*h1Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, ErrClosed
	}
	if t.protos[key] == tlsdial.ProtoHTTP1 || !t.allows(tlsdial.ProtoH2) {
		t.mu.Unlock()
		return t.h1Get(ctx, key, fresh, t.h1DialTLS(tgt, key))
	}
	call := t.dialing[key]
	if call == nil {
		call = &dialCall{done: make(chan struct{})}
		if t.dialing == nil {
			t.dialing = make(map[string]*dialCall)
		}
		t.dialing[key] = call
		go t.sharedDial(call, tgt, key)
	}
	call.waiters++
	t.mu.Unlock()

	select {
	case <-call.done:
	case <-ctx.Done():
	}

	t.mu.Lock()
	call.waiters--
	select {
	case <-call.done:
		// Done is closed under t.mu: the result is final, and a waiter
		// that left before it was not counted by sharedDial. The result
		// is used even if ctx expired meanwhile; the caller then closes
		// the connection.
	default:
		t.mu.Unlock()
		return nil, ctx.Err()
	}
	switch {
	case call.err != nil:
		t.mu.Unlock()
		return nil, call.err
	case call.conn == nil:
		t.mu.Unlock()
		return nil, nil
	case !call.taken:
		call.taken = true
		t.mu.Unlock()
		t.h1Adopt(key)
		return t.newH1Conn(key, call.conn), nil
	}
	t.mu.Unlock()
	// Another waiter took the http/1.1 connection: the origin is now
	// learned as http/1.1.
	return t.h1Get(ctx, key, fresh, t.h1DialTLS(tgt, key))
}

// h1DialTLS returns the dial of the HTTP/1.1 pool for key. A connection
// that negotiates h2 goes to the HTTP/2 pool, and the dial returns nil.
func (t *Transport) h1DialTLS(tgt target.Target, key string) func(context.Context) (net.Conn, *tls.ConnectionState, error) {
	return func(ctx context.Context) (net.Conn, *tls.ConnectionState, error) {
		conn, err := t.dialTLS(ctx, tgt, key)
		if err != nil {
			return nil, nil, err
		}
		if conn.ConnectionState().NegotiatedProtocol == tlsdial.ProtoH2 {
			return nil, nil, t.addH2(key, conn)
		}
		std := tlsdial.StdConn{UConn: conn}
		state := std.ConnectionState()
		return std, &state, nil
	}
}

func (t *Transport) newH1Conn(key string, conn *utls.UConn) *h1Conn {
	std := tlsdial.StdConn{UConn: conn}
	state := std.ConnectionState()
	return &h1Conn{Conn: t.newHTTP1(std), t: t, key: key, state: &state}
}

// addH2 puts an h2 connection in the pool. A connection the pool does not
// take, because a usable one is already there, is closed.
func (t *Transport) addH2(key string, conn *utls.UConn) error {
	std := tlsdial.StdConn{UConn: conn}
	used, err := t.h2t().AddConn(key, std)
	if err != nil || !used {
		std.Close()
	}
	return err
}

// sharedDial runs one dial for the waiters of key. An h2 connection enters
// the pool even if every waiter left; an http/1.1 connection nobody waits
// for is closed (R2).
func (t *Transport) sharedDial(call *dialCall, tgt target.Target, key string) {
	ctx, cancel := context.WithTimeout(t.dialContext(), sharedDialTimeout)
	defer cancel()
	conn, err := t.dialTLS(ctx, tgt, key)
	if err == nil && conn.ConnectionState().NegotiatedProtocol == tlsdial.ProtoH2 {
		err = t.addH2(key, conn)
		conn = nil
	}

	t.mu.Lock()
	delete(t.dialing, key)
	call.conn, call.err = conn, err
	var unused *utls.UConn
	if conn != nil && call.waiters == 0 {
		call.taken = true
		unused = conn
	}
	close(call.done)
	t.mu.Unlock()
	if unused != nil {
		unused.Close()
	}
}

// dialContext returns the context of the dials owned by the Transport,
// canceled by Close.
func (t *Transport) dialContext() context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dialCtx == nil {
		t.dialCtx, t.cancelDials = context.WithCancel(context.Background())
	}
	if t.closed {
		t.cancelDials()
	}
	return t.dialCtx
}

// learn records the protocol a new connection of key negotiated. Every new
// connection revalidates it.
func (t *Transport) learn(key, proto string) {
	t.mu.Lock()
	if t.protos == nil {
		t.protos = make(map[string]string)
	}
	t.protos[key] = proto
	t.mu.Unlock()
}
