package order_test

import (
	"context"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
	"github.com/acomerlatto/eidolon-tls/internal/order"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// Two concurrent requests on one HTTP/2 connection, each with its own order,
// reach the server in that order. The lab decodes the HEADERS frames with the
// upstream HPACK decoder.
func TestH2HeaderOrderOnTheWire(t *testing.T) {
	const streams = 2
	arrived := make(chan struct{}, streams)
	release := make(chan struct{})
	srv := lab.Start(t, lab.Options{
		NextProtos: []string{"h2"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Hold every stream until all are open, so they overlap.
			arrived <- struct{}{}
			select {
			case <-release:
			case <-time.After(10 * time.Second):
			}
			io.WriteString(w, "ok")
		}),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := tlsdial.Dial(ctx, "tcp", srv.Addr, tlsdial.Config{
		Spec: func() (*utls.ClientHelloSpec, error) {
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
			return &spec, err
		},
		TLS: &utls.Config{ServerName: lab.ServerName, RootCAs: srv.RootCAs},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path  string
		order order.Order
		want  []string
	}{
		{
			path: "/a",
			order: order.Order{
				Pseudo: []string{":method", ":authority", ":scheme", ":path"},
				Header: []string{"x-b", "user-agent", "accept", "x-a"},
			},
			// Unlisted names follow in alphabetical order; the cookie is
			// split by the engine and keeps its value order.
			want: []string{":method", ":authority", ":scheme", ":path", "x-b", "user-agent", "accept", "x-a", "accept-encoding", "cookie", "cookie"},
		},
		{
			path: "/b",
			order: order.Order{
				Pseudo: []string{":path", ":scheme", ":authority", ":method"},
				Header: []string{"cookie", "accept", "x-a", "x-b", "user-agent", "accept-encoding"},
			},
			want: []string{":path", ":scheme", ":authority", ":method", "cookie", "cookie", "accept", "x-a", "x-b", "user-agent", "accept-encoding"},
		},
	}

	var wg sync.WaitGroup
	errs := make(chan error, streams)
	for _, tt := range tests {
		wg.Go(func() {
			req, _ := http.NewRequestWithContext(order.WithOrder(ctx, tt.order), http.MethodGet, "https://example.com"+tt.path, nil)
			req.Header.Set("Accept", "*/*")
			req.Header.Set("User-Agent", "eidolon-test")
			req.Header.Set("X-A", "a")
			req.Header.Set("X-B", "b")
			req.Header.Set("Cookie", "one=1; two=2")
			resp, err := cc.RoundTrip(req)
			if err != nil {
				errs <- err
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		})
	}
	for range streams {
		select {
		case <-arrived:
		case err := <-errs:
			t.Fatal(err)
		case <-time.After(10 * time.Second):
			t.Fatal("streams did not overlap")
		}
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	frames, err := srv.NextConn(t).H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, f := range frames {
		if f.Type != "HEADERS" {
			continue
		}
		var path string
		names := make([]string, len(f.Headers))
		for i, h := range f.Headers {
			names[i] = h.Name
			if h.Name == ":path" {
				path = h.Value
			}
		}
		got[path] = names
	}
	for _, tt := range tests {
		if !slices.Equal(got[tt.path], tt.want) {
			t.Errorf("%s: header order on the wire\n got %q\nwant %q", tt.path, got[tt.path], tt.want)
		}
	}
}
