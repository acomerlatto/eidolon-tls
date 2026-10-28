package dispatch

import (
	"context"
	"net"
	"testing"
	"time"
)

// A fresh acquire at the limit, with idle connections and no free slot,
// closes one idle connection and takes its slot instead of waiting for a
// release that would never come.
func TestH1AcquireFreshAtLimit(t *testing.T) {
	tr := &Transport{MaxConnsPerHost: 2}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const key = "https://example.com:443 example.com:443"
	for range 2 {
		if c, err := tr.h1Acquire(ctx, key, false); c != nil || err != nil {
			t.Fatalf("acquire: %v, %v; want a slot", c, err)
		}
	}
	var peers []net.Conn
	for range 2 {
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		peers = append(peers, server)
		tr.h1Put(&h1Conn{Conn: tr.newHTTP1(client), t: tr, key: key})
	}

	c, err := tr.h1Acquire(ctx, key, true)
	if c != nil || err != nil {
		t.Fatalf("fresh acquire: %v, %v; want a slot", c, err)
	}
	closed := 0
	for _, p := range peers {
		p.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := p.Read(make([]byte, 1)); err != nil && !isTimeout(err) {
			closed++
		}
	}
	tr.mu.Lock()
	h := tr.h1[key]
	idle, open := len(h.idle), h.open
	tr.mu.Unlock()
	if closed != 1 || idle != 1 || open != 2 {
		t.Fatalf("%d closed, %d idle, %d open; want 1, 1, 2", closed, idle, open)
	}

	// Without fresh, the idle connection is reused.
	if c, err := tr.h1Acquire(ctx, key, false); c == nil || err != nil {
		t.Fatalf("acquire: %v, %v; want the idle connection", c, err)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// A fresh acquire waiting at the limit does not take a reused connection
// handed over to it: it closes it and dials in its slot.
func TestH1AcquireFreshGranted(t *testing.T) {
	tr := &Transport{MaxConnsPerHost: 1}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const key = "https://example.com:443 example.com:443"
	if c, err := tr.h1Acquire(ctx, key, false); c != nil || err != nil {
		t.Fatalf("acquire: %v, %v; want a slot", c, err)
	}
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	busy := &h1Conn{Conn: tr.newHTTP1(client), t: tr, key: key}

	type result struct {
		c   *h1Conn
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := tr.h1Acquire(ctx, key, true)
		done <- result{c, err}
	}()
	for {
		tr.mu.Lock()
		waiting := len(tr.h1[key].waiters)
		tr.mu.Unlock()
		if waiting == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	tr.h1Put(busy) // handed to the waiter

	r := <-done
	if r.c != nil || r.err != nil {
		t.Fatalf("fresh acquire: %v, %v; want a slot", r.c, r.err)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the reused connection was not closed: %v", err)
	}
	tr.mu.Lock()
	open := tr.h1[key].open
	tr.mu.Unlock()
	if open != 1 {
		t.Fatalf("%d open, want 1", open)
	}
}
