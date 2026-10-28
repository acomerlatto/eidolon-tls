package dispatch

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/http/httpguts"

	"github.com/acomerlatto/eidolon-tls/internal/http1"
)

// DefaultMaxConnsPerHost is the HTTP/1.1 connection limit per key, as in
// Chrome.
const DefaultMaxConnsPerHost = 6

// h1Conn is a pooled HTTP/1.1 connection of one key.
type h1Conn struct {
	*http1.Conn
	t     *Transport
	key   string
	state *tls.ConnectionState // nil over http://
	// served counts the requests sent before the current one; a reused
	// connection may have been lost while idle.
	served int
	once   sync.Once
}

// close closes the connection and frees its slot.
func (c *h1Conn) close() {
	c.once.Do(func() {
		c.Conn.Close()
		c.t.h1Closed(c)
	})
}

// h1Host holds the HTTP/1.1 connections of one key. Guarded by
// Transport.mu.
type h1Host struct {
	idle []*h1Conn // most recently used last
	// open counts the connections of the key, idle, busy or being
	// dialed.
	open    int
	waiters []*h1Waiter
}

// h1Waiter waits for an idle connection or a free slot. grant receives
// the connection, or nil for a slot to dial.
type h1Waiter struct {
	grant chan *h1Conn
}

func (t *Transport) maxConnsPerHost() int {
	if t.MaxConnsPerHost > 0 {
		return t.MaxConnsPerHost
	}
	return DefaultMaxConnsPerHost
}

func (t *Transport) h1HostLocked(key string) *h1Host {
	h := t.h1[key]
	if h == nil {
		h = &h1Host{}
		if t.h1 == nil {
			t.h1 = make(map[string]*h1Host)
		}
		t.h1[key] = h
	}
	return h
}

// h1Acquire returns an idle connection of key, or nil with a slot to dial
// a new one. At the limit it waits, in arrival order, until ctx ends.
//
// fresh asks for a slot even when idle connections exist, for a replay
// after a lost idle connection (section 6.3: on a new connection); the
// others idle since then are suspect too. At the limit, an idle
// connection is closed to make room, and a reused one handed over while
// waiting is closed as well.
func (t *Transport) h1Acquire(ctx context.Context, key string, fresh bool) (*h1Conn, error) {
	t.mu.Lock()
	for {
		if t.closed {
			t.mu.Unlock()
			return nil, ErrClosed
		}
		h := t.h1HostLocked(key)
		free := h.open < t.maxConnsPerHost()
		if n := len(h.idle); n > 0 && !(fresh && free) {
			c := h.idle[n-1]
			h.idle = h.idle[:n-1]
			t.mu.Unlock()
			if c.Reuse() && !fresh {
				return c, nil
			}
			c.close() // closed or written to by the server while idle
			t.mu.Lock()
			continue
		}
		if free {
			h.open++
			t.mu.Unlock()
			return nil, nil
		}
		w := &h1Waiter{grant: make(chan *h1Conn, 1)}
		h.waiters = append(h.waiters, w)
		t.mu.Unlock()

		select {
		case c := <-w.grant:
			if c == nil || !fresh {
				return c, nil
			}
			c.close()
			t.mu.Lock()
			continue
		case <-ctx.Done():
		}
		t.mu.Lock()
		if i := slices.Index(h.waiters, w); i >= 0 {
			h.waiters = slices.Delete(h.waiters, i, i+1)
			t.mu.Unlock()
			return nil, ctx.Err()
		}
		t.mu.Unlock()
		// Granted meanwhile: give it to the next one.
		if c := <-w.grant; c != nil {
			t.h1Put(c)
		} else {
			t.h1Release(key)
		}
		return nil, ctx.Err()
	}
}

// h1Adopt counts a connection dialed outside a slot, such as the result
// of a shared dial.
func (t *Transport) h1Adopt(key string) {
	t.mu.Lock()
	t.h1HostLocked(key).open++
	t.mu.Unlock()
}

// h1Release frees a slot that holds no connection: the dial failed or
// negotiated h2.
func (t *Transport) h1Release(key string) {
	t.mu.Lock()
	h := t.h1HostLocked(key)
	if len(h.waiters) > 0 {
		t.grantLocked(h, nil) // the slot passes to the waiter
	} else {
		h.open--
	}
	t.mu.Unlock()
}

// h1Closed frees the slot of a closed connection.
func (t *Transport) h1Closed(c *h1Conn) {
	t.mu.Lock()
	h := t.h1HostLocked(c.key)
	if i := slices.Index(h.idle, c); i >= 0 {
		h.idle = slices.Delete(h.idle, i, i+1)
	}
	if len(h.waiters) > 0 && !t.closed {
		t.grantLocked(h, nil)
	} else {
		h.open--
	}
	t.mu.Unlock()
}

// h1Put returns a connection whose response ended to the pool: to the
// first waiter, or idle, watched until it is reused.
func (t *Transport) h1Put(c *h1Conn) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		c.close()
		return
	}
	h := t.h1HostLocked(c.key)
	if len(h.waiters) > 0 {
		t.grantLocked(h, c)
		t.mu.Unlock()
		return
	}
	// The watch starts before the connection is visible as idle, so
	// whoever takes it next stops the watch in Reuse.
	c.Watch(func() {
		t.mu.Lock()
		idle := slices.Contains(h.idle, c)
		t.mu.Unlock()
		if idle {
			c.close()
		}
	})
	h.idle = append(h.idle, c)
	t.mu.Unlock()
}

func (t *Transport) grantLocked(h *h1Host, c *h1Conn) {
	w := h.waiters[0]
	h.waiters = h.waiters[1:]
	w.grant <- c
}

// stopH1Locked hands every waiter a slot: its dial then fails with
// ErrClosed. Called by Close.
func (t *Transport) stopH1Locked() {
	for _, h := range t.h1 {
		for len(h.waiters) > 0 {
			h.open++
			t.grantLocked(h, nil)
		}
	}
}

// closeIdleH1 closes the idle HTTP/1.1 connections.
func (t *Transport) closeIdleH1() {
	t.mu.Lock()
	var idle []*h1Conn
	for _, h := range t.h1 {
		idle = append(idle, h.idle...)
		h.idle = nil
	}
	t.mu.Unlock()
	for _, c := range idle {
		c.Reuse() // stops the watch
		c.close()
	}
}

// h1Get returns a connection of key for one request: idle, or dialed in a
// free slot; with fresh, always dialed (h1Acquire). A dial that negotiates h2 pools the connection and returns
// nil, so the request goes back to the HTTP/2 pool.
func (t *Transport) h1Get(ctx context.Context, key string, fresh bool, dial func(context.Context) (net.Conn, *tls.ConnectionState, error)) (*h1Conn, error) {
	c, err := t.h1Acquire(ctx, key, fresh)
	if err != nil || c != nil {
		return c, err
	}
	conn, state, err := dial(ctx)
	if err != nil {
		t.h1Release(key)
		return nil, err
	}
	if conn == nil { // h2, already pooled
		t.h1Release(key)
		return nil, nil
	}
	return &h1Conn{Conn: t.newHTTP1(conn), t: t, key: key, state: state}, nil
}

// sendH1 sends req on c. The connection returns to the pool when the body
// reaches EOF and keep-alive allows it; a body closed before the end
// closes it (section 6.3: no unbounded drain).
//
// On failure, again is the request to send on a new connection when
// section 6.3 allows it: nothing was written, or the reused idle connection
// was lost and the request can be replayed.
func (t *Transport) sendH1(c *h1Conn, req *http.Request) (resp *http.Response, again *http.Request, err error) {
	ctx := req.Context()
	watched, body := watchBody(req)
	stop := context.AfterFunc(ctx, c.close)
	resp, err = c.RoundTrip(watched, t.Spelling)
	closeBody(req)
	if err != nil {
		lost := connLost(err)
		if stop() && c.Sent() == 0 && !lost {
			t.h1Put(c) // the request never reached the wire
		} else {
			c.close()
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		if !lost || body.failed() || t.isClosed() {
			return nil, nil, err
		}
		var ok bool
		switch {
		case c.Sent() == 0:
			again, ok = rewindBody(req)
		case c.served > 0:
			again, ok = rewind(req)
		}
		if !ok {
			return nil, nil, err
		}
		return nil, again, err
	}
	resp.TLS = c.state
	keep := c.KeepAlive(resp) && !req.Close && !closeRequested(req.Header)
	if resp.Body == http.NoBody {
		finishH1(c, stop, keep)
		return resp, nil, nil
	}
	resp.Body = &h1Body{ReadCloser: resp.Body, c: c, stop: stop, keep: keep, ctx: ctx}
	return resp, nil, nil
}

// finishH1 ends the use of c by one response: back to the pool if it may
// be reused and the context did not close it, closed otherwise.
func finishH1(c *h1Conn, stop func() bool, keep bool) {
	if stop() && keep {
		c.served++
		c.t.h1Put(c)
	} else {
		c.close()
	}
}

// closeRequested reports whether the request asked to close the
// connection with "Connection: close".
func closeRequested(h http.Header) bool {
	for k, vv := range h {
		if strings.EqualFold(k, "connection") && httpguts.HeaderValuesContainsToken(vv, "close") {
			return true
		}
	}
	return false
}

// h1Body hands the connection back on EOF and closes it on an early
// Close or a read error.
type h1Body struct {
	io.ReadCloser
	c    *h1Conn
	stop func() bool
	keep bool
	once sync.Once
	ctx  context.Context
}

func (b *h1Body) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(func() { finishH1(b.c, b.stop, b.keep && err == io.EOF) })
		// The context closed the connection: report its cause, as the H2
		// engine does, not the closed connection.
		if ctxErr := b.ctx.Err(); ctxErr != nil && err != io.EOF {
			err = ctxErr
		}
	}
	return n, err
}

// Close closes the connection before the body: an HTTP/1.1 body from
// http.ReadResponse reads to the end on Close, which never returns for a
// body the server does not finish.
func (b *h1Body) Close() error {
	b.once.Do(func() {
		b.stop()
		b.c.close()
	})
	b.ReadCloser.Close()
	return nil
}
