package eidolon_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
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
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header[eidolon.HeaderOrderKey] = []string{"x-b", "accept"}
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

// http.Client copies the order keys to a redirected request: the order
// applies to the next request as well.
func TestOrderFollowsRedirect(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next", http.StatusFound)
		}
	})})
	c := newClient(t, srv, eidolon.WithDefaultOrder(eidolon.Order{Header: []string{"x-b", "host"}}))
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/start", nil)
	req.Header[eidolon.HeaderOrderKey] = []string{"x-c"}
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

// The keys of a request take precedence over the client order, each list
// on its own, are never sent and stay in the caller's Header.
func TestHeaderOrderKeys(t *testing.T) {
	client := eidolon.WithDefaultOrder(eidolon.Order{
		Pseudo: []string{":method", ":path", ":authority", ":scheme"},
		Header: []string{"x-a", "x-b", "x-c"},
	})
	for _, tt := range []struct {
		name   string
		pseudo []string
		header []string
		want   []string
	}{
		{"both", []string{":method", ":authority", ":scheme", ":path"}, []string{"x-c", "x-b"},
			[]string{":method", ":authority", ":scheme", ":path", "x-c", "x-b", "x-a"}},
		{"header only", nil, []string{"x-b"},
			[]string{":method", ":path", ":authority", ":scheme", "x-b", "x-a", "x-c"}},
		{"pseudo only", []string{":authority", ":method", ":path", ":scheme"}, nil,
			[]string{":authority", ":method", ":path", ":scheme", "x-a", "x-b", "x-c"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{})
			c := newClient(t, srv, client)
			req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
			for _, h := range []string{"X-A", "X-B", "X-C"} {
				req.Header.Set(h, "1")
			}
			if tt.pseudo != nil {
				req.Header[eidolon.PHeaderOrderKey] = tt.pseudo
			}
			if tt.header != nil {
				req.Header[eidolon.HeaderOrderKey] = tt.header
			}
			before := req.Header.Clone()
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if !reflect.DeepEqual(req.Header, before) {
				t.Fatalf("Header changed to %v", req.Header)
			}
			if got := headerNames(t, srv.NextConn(t)); !slices.Equal(got, tt.want) {
				t.Fatalf("sent %q\nwant %q", got, tt.want)
			}
		})
	}
	t.Run("http/1.1", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
		c := newClient(t, srv, client)
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.Header.Set("X-A", "1")
		req.Header.Set("X-B", "1")
		req.Header[eidolon.HeaderOrderKey] = []string{"x-b", "host"}
		req.Header[eidolon.PHeaderOrderKey] = []string{":path"}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		want := "GET / HTTP/1.1\r\nX-B: 1\r\nHost: example.com\r\nX-A: 1\r\n\r\n"
		if got := string(srv.NextConn(t).Bytes()); got != want {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})
}

// headerNames returns the names of the first HEADERS frame c received.
func headerNames(t *testing.T, c *lab.Conn) []string {
	t.Helper()
	frames, err := c.H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if f.Type == "HEADERS" {
			var names []string
			for _, h := range f.Headers {
				names = append(names, h.Name)
			}
			return names
		}
	}
	t.Fatal("no HEADERS frame")
	return nil
}

// In exact mode PHeaderOrderKey still orders the pseudo-headers; the rest
// of Header is ignored.
func TestWithExactHeadersPseudoKey(t *testing.T) {
	srv := lab.Start(t, lab.Options{})
	c := newClient(t, srv)
	ctx := eidolon.WithExactHeaders(context.Background(), eidolon.HeaderField{Name: "accept", Value: "*/*"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	req.Header[eidolon.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	req.Header[eidolon.HeaderOrderKey] = []string{"x-a"}
	req.Header.Set("X-A", "ignored")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	want := []string{":method", ":authority", ":scheme", ":path", "accept"}
	if got := headerNames(t, srv.NextConn(t)); !slices.Equal(got, want) {
		t.Fatalf("sent %q\nwant %q", got, want)
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
