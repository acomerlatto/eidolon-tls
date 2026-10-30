package dns

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Exchanger sends a query and returns the query it sent last, with the
// response to it.
type Exchanger interface {
	Exchange(ctx context.Context, name string, qtype dnsmessage.Type) (query, resp []byte, err error)
}

const (
	// DefaultTimeout bounds a lookup, as Chrome's minimum DNS transaction
	// timeout (kDnsMinTransactionTimeout).
	DefaultTimeout = 12 * time.Second
	// DefaultMaxEntries bounds the cache, as Chrome's HostCache
	// (kDefaultMaxEntries).
	DefaultMaxEntries = 1000
	// DefaultMaxQueries bounds the queries in progress, as Chrome's
	// resolver jobs (kDefaultMaxSystemTasks).
	DefaultMaxQueries = 64
)

// Resolver looks up the HTTPS records of origins over an Exchanger, with
// a cache of its own: Found and NoData answers are kept for their TTL, the
// others are not. An expired entry stays until a new answer replaces it or
// a full cache drops it. Concurrent lookups of one name share one query, which
// ends when every caller has left or after Timeout. Beyond MaxQueries in
// progress, the queries wait in line.
type Resolver struct {
	Exchanger Exchanger
	// Timeout bounds a query from its start, after its wait in line; zero
	// means DefaultTimeout.
	Timeout time.Duration
	// MaxEntries bounds the cache; zero means DefaultMaxEntries.
	MaxEntries int
	// MaxQueries bounds the queries in progress; zero means
	// DefaultMaxQueries.
	MaxQueries int
	// Local, when set, reports the hosts resolved without DNS, whose
	// answer is NoData without a query.
	Local func(host string) bool

	mu     sync.Mutex
	cache  map[string]entry
	calls  map[string]*call
	slots  chan struct{} // one per query in progress
	closed bool
}

// ErrClosed reports a lookup after Close.
var ErrClosed = errors.New("dns: resolver closed")

// Close ends the queries in progress, whose callers get a Failed answer,
// and makes the lookups that would need a new query fail with ErrClosed.
func (r *Resolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, c := range r.calls {
		c.cancel()
	}
}

type entry struct {
	https   HTTPS
	expires time.Time
}

// call is a query in progress, shared by its waiters.
type call struct {
	done    chan struct{}
	https   HTTPS
	waiters int
	cancel  context.CancelFunc
}

// QueryName returns the name of the HTTPS query for host and port, a
// host name without the final dot: the host on port 443, and
// _port._https.host on another port (RFC 9460, Section 9.1), as Chrome.
func QueryName(host string, port uint16) string {
	if port == 443 {
		return host
	}
	return "_" + strconv.Itoa(int(port)) + "._https." + host
}

// HTTPS returns the HTTPS answer for the origin of host and port, from the
// cache or from a query. host may end with a dot. It returns at the end of ctx with a Failed answer
// whose Err is ctx's.
func (r *Resolver) HTTPS(ctx context.Context, host string, port uint16) HTTPS {
	if r.Local != nil && r.Local(host) {
		return HTTPS{Status: NoData}
	}
	// A final dot only says the name is complete: it is asked and its
	// records read as without it.
	host = strings.TrimSuffix(host, ".")
	name := QueryName(host, port)
	r.mu.Lock()
	if e, ok := r.cache[name]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.https
	}
	// A query whose callers all left ends: a later caller starts another,
	// as Chrome a new job.
	c := r.calls[name]
	if c == nil || c.waiters == 0 {
		if r.closed {
			r.mu.Unlock()
			return failed(ErrClosed)
		}
		qctx, cancel := context.WithCancel(context.Background())
		c = &call{done: make(chan struct{}), cancel: cancel}
		if r.calls == nil {
			r.calls = make(map[string]*call)
			n := r.MaxQueries
			if n == 0 {
				n = DefaultMaxQueries
			}
			r.slots = make(chan struct{}, n)
		}
		r.calls[name] = c
		go r.lookup(qctx, c, name, host, port)
	}
	c.waiters++
	r.mu.Unlock()

	select {
	case <-c.done:
		return c.https
	case <-ctx.Done():
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c.waiters--
	if c.waiters == 0 {
		c.cancel()
	}
	return failed(ctx.Err())
}

// lookup runs the query of c and keeps its answer.
func (r *Resolver) lookup(ctx context.Context, c *call, name, host string, port uint16) {
	defer c.cancel()
	h := r.query(ctx, name, host, port)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls[name] == c {
		delete(r.calls, name)
	}
	// Only Found and NoData have a TTL. Kept before the callers get the
	// answer, which is then in the cache for them.
	if h.TTL > 0 {
		r.store(name, entry{h, time.Now().Add(h.TTL)})
	}
	c.https = h
	close(c.done)
}

// query waits in line for a slot, then sends the query of name within
// Timeout and reads its answer.
func (r *Resolver) query(ctx context.Context, name, host string, port uint16) HTTPS {
	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		return failed(ctx.Err())
	}
	defer func() { <-r.slots }()
	timeout := r.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	q, resp, err := r.Exchanger.Exchange(ctx, name, TypeHTTPS)
	if err != nil {
		return failed(err)
	}
	return Parse(q, resp, host, port)
}

// store adds e to the cache. A full cache first drops the entry that
// expires first, as Chrome's HostCache::EvictOneEntry.
func (r *Resolver) store(name string, e entry) {
	limit := r.MaxEntries
	if limit == 0 {
		limit = DefaultMaxEntries
	}
	if r.cache == nil {
		r.cache = make(map[string]entry)
	}
	if _, ok := r.cache[name]; !ok && len(r.cache) >= limit {
		first := ""
		for n, old := range r.cache {
			if first == "" || old.expires.Before(r.cache[first].expires) {
				first = n
			}
		}
		delete(r.cache, first)
	}
	r.cache[name] = e
}
