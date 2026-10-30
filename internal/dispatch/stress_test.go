package dispatch_test

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Concurrent HTTP/1.1 requests over a server that answers with
// Connection: close, closes its keep-alive connections right after an
// answer, or sends bodies the client closes early: every GET is answered,
// replayed when its reused connection was lost, and no connection carries
// two requests at once.
func TestH1Stress(t *testing.T) {
	var mu sync.Mutex
	active := map[string]int{}
	overlap := 0
	enter := func(r *http.Request) func() {
		mu.Lock()
		active[r.RemoteAddr]++
		if active[r.RemoteAddr] > 1 {
			overlap++
		}
		mu.Unlock()
		return func() {
			mu.Lock()
			active[r.RemoteAddr]--
			mu.Unlock()
		}
	}
	big := strings.Repeat("x", 64<<10)
	srv, base := h1Lab(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leave := enter(r)
		switch r.URL.Path {
		case "/close":
			w.Header().Set("Connection", "close")
			io.WriteString(w, "ok")
		case "/early":
			io.WriteString(w, big)
		case "/dropped":
			// Answered, then the keep-alive connection closes under the
			// client.
			conn, buf, err := http.NewResponseController(w).Hijack()
			if err != nil {
				leave()
				return
			}
			buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			buf.Flush()
			leave()
			time.AfterFunc(time.Millisecond, func() { conn.Close() })
			return
		default:
			io.WriteString(w, "ok")
		}
		leave()
	}))
	tr := transport(srv)
	tr.MaxConnsPerHost = 3
	defer tr.Close()
	paths := []string{"/", "/close", "/early", "/dropped"}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			rng := rand.New(rand.NewPCG(uint64(g), 1))
			for range 40 {
				path := paths[rng.IntN(len(paths))]
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
				resp, err := tr.RoundTrip(req)
				if err != nil {
					cancel()
					t.Errorf("GET %s: %v", path, err)
					return
				}
				if path == "/early" {
					io.CopyN(io.Discard, resp.Body, 10)
				} else if b, err := io.ReadAll(resp.Body); err != nil || string(b) != "ok" {
					t.Errorf("GET %s: %q, %v", path, b, err)
				}
				resp.Body.Close()
				cancel()
			}
		})
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if overlap != 0 {
		t.Errorf("%d requests on a connection busy with another", overlap)
	}
}
