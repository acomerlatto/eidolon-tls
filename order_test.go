package eidolon_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

func TestHeaderOptionsRejected(t *testing.T) {
	for _, tt := range []struct {
		name string
		opt  eidolon.Option
	}{
		{"invalid name", eidolon.WithHeaderSpelling("X A")},
		{"empty name", eidolon.WithHeaderSpelling("")},
		{"two spellings", eidolon.WithHeaderSpelling("X-A", "x-a")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if c, err := eidolon.New(eidolon.WithClientHello(chromeSpec), tt.opt); !errors.Is(err, eidolon.ErrConfig) || c != nil {
				t.Fatalf("New = %v, %v; want nil, ErrConfig", c, err)
			}
		})
	}
}

// The client order and spelling reach the wire, behind the order of the
// request, and the order lists are copied.
func TestDefaultOrderAndSpelling(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	list := []string{"host", "user-agent", "accept", "x-a"}
	c := newClient(t, srv,
		eidolon.WithDefaultOrder(eidolon.Order{Header: list}),
		eidolon.WithHeaderSpelling("x-a", "X-B", "X-B"))
	list[0] = "x-z"
	ctx := eidolon.WithOrder(context.Background(), eidolon.Order{Header: []string{"x-b", "accept"}})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	for _, h := range []string{"Accept", "X-A", "X-B", "X-Z", "User-Agent"} {
		req.Header.Set(h, "1")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	want := "GET / HTTP/1.1\r\nX-B: 1\r\nAccept: 1\r\nHost: example.com\r\nUser-Agent: 1\r\nx-a: 1\r\nX-Z: 1\r\n\r\n"
	if got := string(srv.NextConn(t).Bytes()); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// http.Client follows a redirect with the context of the request: the
// order applies to the next request as well.
func TestOrderFollowsRedirect(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next", http.StatusFound)
		}
	})})
	c := newClient(t, srv, eidolon.WithDefaultOrder(eidolon.Order{Header: []string{"x-b", "host"}}))
	ctx := eidolon.WithOrder(context.Background(), eidolon.Order{Header: []string{"x-c"}})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/start", nil)
	req.Header.Set("X-A", "1")
	req.Header.Set("X-B", "1")
	req.Header.Set("X-C", "1")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	got := string(srv.NextConn(t).Bytes())
	want := "GET /next HTTP/1.1\r\nX-C: 1\r\nX-B: 1\r\nHost: example.com\r\n"
	if !strings.Contains(got, want) {
		t.Fatalf("sent %q\nwant a request starting with %q", got, want)
	}
}

// A redirect in exact mode fails without sending the next request.
func TestWithExactHeadersRedirect(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := lab.Start(t, lab.Options{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		http.Redirect(w, r, "/next", http.StatusFound)
	})})
	c := newClient(t, srv)
	ctx := eidolon.WithExactHeaders(context.Background(),
		eidolon.HeaderField{Name: "Host", Value: "example.com"},
		eidolon.HeaderField{Name: "accept", Value: "*/*"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/start", nil)
	if _, err := c.Do(req); !errors.Is(err, eidolon.ErrExactHeadersRedirect) {
		t.Fatalf("err = %v, want ErrExactHeadersRedirect", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || paths[0] != "/start" {
		t.Fatalf("server saw %v", paths)
	}
}

// WithExactHeaders reaches the HTTP/1.1 engine: the fields as given and
// nothing from Request.Header or the spelling table.
func TestWithExactHeadersH1(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	c := newClient(t, srv, eidolon.WithHeaderSpelling("ACCEPT"))
	ctx := eidolon.WithExactHeaders(context.Background(),
		eidolon.HeaderField{Name: "host", Value: "example.com"},
		eidolon.HeaderField{Name: "accept", Value: "*/*"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "ignored")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	want := "GET / HTTP/1.1\r\nhost: example.com\r\naccept: */*\r\n\r\n"
	if got := string(srv.NextConn(t).Bytes()); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
