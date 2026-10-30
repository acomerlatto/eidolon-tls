package dispatch

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/acomerlatto/eidolon-tls/internal/http2"
)

// connLimit bounds the connections of a transport and of its children
// (MaxConns): in use, idle or being opened, as Chrome's
// TransportClientSocketPool counts its sockets, an HTTP/2 session
// included.
type connLimit struct {
	owner *Transport // closes the limit at its Close
	mu    sync.Mutex
	max   int
	n     int
	// waiting counts the acquires waiting for a slot.
	waiting int
	// h2 are the HTTP/2 engines of the transports under the limit.
	h2 []*http2.Transport
	// freed is closed, and replaced, when a slot is freed or the limit
	// closed.
	freed  chan struct{}
	closed bool
}

// slot is a connection's place under a connLimit. Nil is a place without
// limit.
type slot struct {
	l     *connLimit
	taken atomic.Bool
	once  sync.Once
}

// limiter returns the limit of t, nil without MaxConns.
func (t *Transport) limiter() *connLimit {
	if t.MaxConns <= 0 {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.limit == nil {
		t.limit = &connLimit{owner: t, max: t.MaxConns, freed: make(chan struct{})}
	}
	return t.limit
}

// acquire returns a slot of l, waiting for one until ctx ends. Over the
// limit, as Chrome's TransportClientSocketPool, it first closes an idle
// HTTP/1.1 connection of the owner (CloseOneIdleSocketExceptInGroup);
// without one, every HTTP/2 connection without streams under the limit
// (TryToCloseSocketsInLayeredPools), and while it waits, an HTTP/2
// connection closes when its last stream ends (stalled).
func (l *connLimit) acquire(ctx context.Context) (*slot, error) {
	if l == nil {
		return nil, nil
	}
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, ErrClosed
		}
		if l.n < l.max {
			l.n++
			l.mu.Unlock()
			return &slot{l: l}, nil
		}
		freed := l.freed
		l.mu.Unlock()
		if l.owner.closeOneIdleH1() {
			continue
		}
		l.mu.Lock()
		l.waiting++
		h2 := slices.Clone(l.h2)
		l.mu.Unlock()
		for _, t := range h2 {
			t.CloseIdleConnections()
		}
		var err error
		select {
		case <-freed:
		case <-ctx.Done():
			err = ctx.Err()
		}
		l.mu.Lock()
		l.waiting--
		l.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
}

// join puts h2 under l: its connections close when idle while l is
// stalled.
func (l *connLimit) join(h2 *http2.Transport) {
	l.mu.Lock()
	l.h2 = append(l.h2, h2)
	l.mu.Unlock()
	h2.CloseIdleIf = l.stalled
}

// stalled reports whether an acquire waits for a slot, as Chrome's
// IsPoolStalled.
func (l *connLimit) stalled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.waiting > 0
}

// wake makes the waits for a slot look again for an idle connection to
// close. Nil does nothing.
func (l *connLimit) wake() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		close(l.freed)
		l.freed = make(chan struct{})
	}
}

// close makes every wait for a slot fail with ErrClosed.
func (l *connLimit) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		close(l.freed)
	}
}

// take marks s as given to a connection; false if it already was, or for
// nil.
func (s *slot) take() bool {
	return s != nil && s.taken.CompareAndSwap(false, true)
}

// release frees s, once.
func (s *slot) release() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.l.mu.Lock()
		s.l.n--
		s.l.mu.Unlock()
		s.l.wake()
	})
}

// closeOneIdleH1 closes the idle HTTP/1.1 connection used least recently
// of the first key, in order, that has one, and reports whether there was
// one.
func (t *Transport) closeOneIdleH1() bool {
	t.mu.Lock()
	keys := make([]string, 0, len(t.h1))
	for k, h := range t.h1 {
		if len(h.idle) > 0 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		t.mu.Unlock()
		return false
	}
	h := t.h1[slices.Min(keys)]
	c := h.idle[0]
	h.idle = h.idle[1:]
	t.mu.Unlock()
	c.Reuse() // stops the watch
	c.close()
	return true
}
