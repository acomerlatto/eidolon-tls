package dispatch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// h1Open returns the HTTP/1.1 slots taken, over every key.
func (t *Transport) h1Open() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, h := range t.h1 {
		n += h.open
	}
	return n
}

// The shared dial of an origin not yet learned holds an HTTP/1.1 slot from
// its start, as a connection being opened counts in Chrome's limit: a
// request that learns http/1.1 meanwhile cannot dial past the limit. The
// slot passes to the request that takes the connection, and is freed when
// the dial fails or negotiates h2.
func TestSharedDialHoldsSlot(t *testing.T) {
	for _, tt := range []struct {
		name   string
		protos []string
		fail   bool
		after  int // slots taken once the response was read
	}{
		{"http/1.1", []string{"http/1.1"}, false, 1},
		{"h2", []string{"h2"}, false, 0},
		{"failed", []string{"http/1.1"}, true, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: tt.protos})
			tr := &Transport{
				Spec: func() (*utls.ClientHelloSpec, error) {
					spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
					return &spec, err
				},
				TLS: &utls.Config{RootCAs: srv.RootCAs},
			}
			defer tr.Close()
			during := -1
			tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				during = tr.h1Open()
				if tt.fail {
					return nil, errors.New("refused")
				}
				var d net.Dialer
				return d.DialContext(ctx, network, srv.Addr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
			resp, err := tr.RoundTrip(req)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			} else if !tt.fail {
				t.Fatal(err)
			}
			if during != 1 {
				t.Fatalf("%d slots taken during the shared dial, want 1", during)
			}
			if n := tr.h1Open(); n != tt.after {
				t.Fatalf("%d slots taken after it, want %d", n, tt.after)
			}
		})
	}
}

// An http/1.1 connection of a shared dial that every request left is
// closed (R2), and its slot freed.
func TestSharedDialAbandonedFreesSlot(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	release := make(chan struct{})
	tr := &Transport{
		Spec: func() (*utls.ClientHelloSpec, error) {
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
			return &spec, err
		},
		TLS: &utls.Config{RootCAs: srv.RootCAs},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			<-release
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Addr)
		},
	}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	if _, err := tr.RoundTrip(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want its deadline", err)
	}
	close(release)
	select {
	case <-srv.NextConn(t).Done():
	case <-time.After(5 * time.Second):
		t.Fatal("abandoned connection kept open")
	}
	if n := tr.h1Open(); n != 0 {
		t.Fatalf("%d slots taken, want 0", n)
	}
}
