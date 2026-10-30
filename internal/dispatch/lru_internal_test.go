package dispatch

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// An lru keeps its max most recently used keys: get and put make a key the
// most recent, and put drops the least recent one when full.
func TestLRU(t *testing.T) {
	var none *lru[int]
	if _, ok := none.get("a"); ok {
		t.Error("nil lru has a key")
	}
	l := newLRU[int](2)
	l.put("a", 1)
	l.put("b", 2)
	l.get("a")    // b is now the least recent
	l.put("c", 3) // drops b
	if _, ok := l.get("b"); ok {
		t.Error("b kept, want it dropped as the least recent")
	}
	l.put("a", 4) // replaces, drops nothing
	if v, ok := l.get("a"); !ok || v != 4 {
		t.Errorf("a = %d, %v; want 4", v, ok)
	}
	if v, ok := l.get("c"); !ok || v != 3 || len(l.items) != 2 || l.order.Len() != 2 {
		t.Errorf("c = %d, %v with %d items; want 3 of 2", v, ok, len(l.items))
	}
}

// The protocols learned and the keys requiring HTTP/1.1 are bounded as in
// Chrome, for a client that reaches many origins.
func TestServerInfoBounded(t *testing.T) {
	tr := &Transport{}
	for i := range 510 {
		tr.learn(strconv.Itoa(i), "h2")
	}
	for i := range 110 {
		tr.requireH1("r" + strconv.Itoa(i))
	}
	if n := tr.protos.order.Len(); n != 500 {
		t.Errorf("%d protocols kept, want 500", n)
	}
	if n := tr.h1Required.order.Len(); n != 100 {
		t.Errorf("%d keys requiring HTTP/1.1, want 100", n)
	}
	if !tr.h1Only("r109") {
		t.Error("the last key requiring HTTP/1.1 is forgotten")
	}
}

// The HTTP/1.1 pool of a key goes away with its last connection.
func TestH1PoolDropped(t *testing.T) {
	tr := &Transport{}
	defer tr.Close()
	const key = "https://example.com:443 example.com:443"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := tr.h1Acquire(ctx, key, false); c != nil || err != nil {
		t.Fatalf("acquire: %v, %v; want a slot", c, err)
	}
	tr.h1Release(key) // the dial failed
	tr.mu.Lock()
	n := len(tr.h1)
	tr.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d pools kept after a failed dial, want none", n)
	}
	client, server := net.Pipe()
	defer server.Close()
	if _, err := tr.h1Acquire(ctx, key, false); err != nil {
		t.Fatal(err)
	}
	tr.h1Put(&h1Conn{Conn: tr.newHTTP1(client), t: tr, key: key})
	tr.CloseIdleConnections()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.h1) != 0 {
		t.Errorf("%d pools kept, want none", len(tr.h1))
	}
}
