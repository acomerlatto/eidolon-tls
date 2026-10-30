package dispatch

import "container/list"

const (
	// maxServerInfo bounds the protocols learned per key, as Chrome's
	// HttpServerProperties bounds its server info (kMaxServerInfoEntries).
	maxServerInfo = 500
	// maxHTTP11Required bounds the keys marked HTTP_1_1_REQUIRED, as
	// Chrome's servers_requiring_http_11_
	// (kMaxServersRequiringHttp11Entries).
	maxHTTP11Required = 100
)

// lru is a map that keeps its max most recently used keys, as Chrome's
// base::LRUCache: get and put make a key the most recent, and put drops
// the least recent one when full. A nil lru is empty.
type lru[V any] struct {
	max   int
	order *list.List // of *lruEntry, the most recent first
	items map[string]*list.Element
}

type lruEntry[V any] struct {
	key string
	val V
}

func newLRU[V any](max int) *lru[V] {
	return &lru[V]{max: max, order: list.New(), items: make(map[string]*list.Element)}
}

func (l *lru[V]) get(key string) (V, bool) {
	if l == nil {
		var zero V
		return zero, false
	}
	e, ok := l.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	l.order.MoveToFront(e)
	return e.Value.(*lruEntry[V]).val, true
}

func (l *lru[V]) put(key string, val V) {
	if e, ok := l.items[key]; ok {
		e.Value.(*lruEntry[V]).val = val
		l.order.MoveToFront(e)
		return
	}
	if l.order.Len() >= l.max {
		last := l.order.Back()
		delete(l.items, last.Value.(*lruEntry[V]).key)
		l.order.Remove(last)
	}
	l.items[key] = l.order.PushFront(&lruEntry[V]{key, val})
}
