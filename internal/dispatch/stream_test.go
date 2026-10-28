package dispatch_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// stalling answers /stall with headers and a first piece of body, then
// waits until release is closed; other paths answer "ok".
func stalling(release <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stall" {
			io.WriteString(w, "ok")
			return
		}
		io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
}

// The deadline of a request covers its body: headers in time return the
// response, and a body still arriving at the deadline fails on Read. The
// client keeps working: over HTTP/2 on the same connection, over HTTP/1.1
// on a new one.
func TestDeadlineDuringBody(t *testing.T) {
	for _, protos := range bothProtos {
		t.Run(protos[0], func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: stalling(release)})
			tr := transport(srv)
			defer tr.Close()
			client := &http.Client{Transport: tr, Timeout: 300 * time.Millisecond}
			resp, err := client.Get("https://example.com/stall")
			if err != nil {
				t.Fatalf("headers: %v", err)
			}
			start := time.Now()
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("body: err = %v, want a timeout", err)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("body failed after %v", d)
			}
			if _, body, err := do(t, tr, http.MethodGet, "https://example.com/next", ""); err != nil || body != "ok" {
				t.Fatalf("next request: %q, %v", body, err)
			}
			want := map[string]int{"h2": 1, "http/1.1": 2}[protos[0]]
			if n := srv.Accepted(); n != want {
				t.Fatalf("%d connections, want %d", n, want)
			}
		})
	}
}

// Cancelling the context, or its deadline, while the body is read fails
// the Read with the context error, not the closed connection; the next
// request works as above.
func TestCancelDuringBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		want error
	}{{"cancel", context.Canceled}, {"deadline", context.DeadlineExceeded}} {
		for _, protos := range bothProtos {
			t.Run(tc.name+"/"+protos[0], func(t *testing.T) {
				release := make(chan struct{})
				defer close(release)
				srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: stalling(release)})
				tr := transport(srv)
				defer tr.Close()
				ctx, cancel := context.WithCancel(context.Background())
				if tc.want == context.DeadlineExceeded {
					ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
				}
				defer cancel()
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/stall", nil)
				resp, err := tr.RoundTrip(req)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				if _, err := io.ReadFull(resp.Body, make([]byte, len("first"))); err != nil {
					cancel()
					t.Fatal(err)
				}
				if tc.want == context.Canceled {
					time.AfterFunc(50*time.Millisecond, cancel)
				}
				_, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				if _, body, err := do(t, tr, http.MethodGet, "https://example.com/next", ""); err != nil || body != "ok" {
					t.Fatalf("next request: %q, %v", body, err)
				}
				want := map[string]int{"h2": 1, "http/1.1": 2}[protos[0]]
				if n := srv.Accepted(); n != want {
					t.Fatalf("%d connections, want %d", n, want)
				}
			})
		}
	}
}

// CloseIdleConnections leaves a response still being read alone: its body
// ends as the server sent it.
func TestCloseIdleKeepsActiveResponse(t *testing.T) {
	for _, protos := range bothProtos {
		t.Run(protos[0], func(t *testing.T) {
			release := make(chan struct{})
			srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "first")
				w.(http.Flusher).Flush()
				<-release
				io.WriteString(w, "-last")
			})})
			tr := transport(srv)
			defer tr.Close()
			req, _ := newRequest(t, http.MethodGet, "https://example.com/", nil)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				close(release)
				t.Fatal(err)
			}
			defer resp.Body.Close()
			head := make([]byte, len("first"))
			if _, err := io.ReadFull(resp.Body, head); err != nil {
				close(release)
				t.Fatal(err)
			}
			tr.CloseIdleConnections()
			close(release)
			rest, err := io.ReadAll(resp.Body)
			if err != nil || string(head)+string(rest) != "first-last" {
				t.Fatalf("body %q%q, %v", head, rest, err)
			}
		})
	}
}

// A body closed twice, or closed while another goroutine reads it,
// releases its HTTP/1.1 connection once: with one connection per host, two
// concurrent requests after it still share one connection, one waiting.
func TestBodyReleasedOnce(t *testing.T) {
	gate := make(chan struct{})
	var mu sync.Mutex
	active, peak := 0, 0
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gate" {
			mu.Lock()
			active++
			peak = max(peak, active)
			mu.Unlock()
			<-gate
			mu.Lock()
			active--
			mu.Unlock()
		}
		io.WriteString(w, "ok")
	})})
	tr := transport(srv)
	tr.MaxConnsPerHost = 1
	defer tr.Close()

	// Read to EOF, then close twice.
	resp, _, err := do(t, tr, http.MethodGet, "https://example.com/a", "")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp.Body.Close()
	// Close while another goroutine reads.
	req, _ := newRequest(t, http.MethodGet, "https://example.com/b", nil)
	resp, err = tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() { io.ReadAll(resp.Body) })
	resp.Body.Close()
	wg.Wait()
	resp.Body.Close()

	var reqs sync.WaitGroup
	for range 2 {
		reqs.Go(func() {
			if _, _, err := do(t, tr, http.MethodGet, "https://example.com/gate", ""); err != nil {
				t.Error(err)
			}
		})
	}
	time.Sleep(200 * time.Millisecond)
	close(gate)
	reqs.Wait()
	if peak != 1 {
		t.Fatalf("%d requests at once, want 1 (one connection per host)", peak)
	}
}
