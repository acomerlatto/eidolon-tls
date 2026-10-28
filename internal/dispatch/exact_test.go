package dispatch_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// h2Streams returns the fields of each HEADERS frame the lab received, by
// stream, as "name: value".
func h2Streams(t *testing.T, c *lab.Conn) map[uint32][]string {
	t.Helper()
	frames, err := c.H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint32][]string{}
	for _, f := range frames {
		if f.Type != "HEADERS" {
			continue
		}
		for _, h := range f.Headers {
			out[f.StreamID] = append(out[f.StreamID], h.Name+": "+h.Value)
		}
	}
	return out
}

// sendCtx sends a request with ctx and reads the body.
func sendCtx(t *testing.T, tr http.RoundTripper, ctx context.Context, method, url string, header http.Header, body string) error {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, method, url, r)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	return err
}

// The client order completes the request order, in both protocols: the
// example of section 7 of the specification, with Host listed by the
// client for HTTP/1.1.
func TestOrderPrecedence(t *testing.T) {
	header := http.Header{"Accept": {"1"}, "X-A": {"2"}, "X-B": {"3"}, "X-Z": {"4"}}
	reqOrder := order.WithOrder(context.Background(), order.Order{Header: []string{"x-b", "accept"}})
	client := &order.Order{
		Pseudo: []string{":method", ":authority", ":scheme", ":path"},
		Header: []string{"host", "user-agent", "accept", "x-a"},
	}
	t.Run("h2", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{})
		tr := transport(srv)
		tr.Order = client
		defer tr.Close()
		if err := sendCtx(t, tr, reqOrder, http.MethodGet, "https://example.com/", header, ""); err != nil {
			t.Fatal(err)
		}
		want := []string{":method: GET", ":authority: example.com", ":scheme: https", ":path: /", "x-b: 3", "accept: 1", "x-a: 2", "x-z: 4"}
		if got := h2Streams(t, srv.NextConn(t))[1]; !slices.Equal(got, want) {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})
	t.Run("http/1.1", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
		tr := transport(srv)
		tr.Order = client
		defer tr.Close()
		if err := sendCtx(t, tr, reqOrder, http.MethodGet, "https://example.com/", header, ""); err != nil {
			t.Fatal(err)
		}
		want := "GET / HTTP/1.1\r\nX-B: 3\r\nAccept: 1\r\nHost: example.com\r\nX-A: 2\r\nX-Z: 4\r\n\r\n"
		if got := string(srv.NextConn(t).Bytes()); got != want {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})
}

// Two concurrent requests with different orders on one HTTP/2 connection
// each keep their own.
func TestOrderConcurrentSameConnection(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{}, 3)
	srv := lab.Start(t, lab.Options{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
		io.WriteString(w, "ok")
	})})
	tr := transport(srv)
	defer tr.Close()
	warmErr := make(chan error, 1)
	go func() {
		warmErr <- sendCtx(t, tr, context.Background(), http.MethodGet, "https://example.com/warm", nil, "")
	}()
	// The first request opens the connection; the two others share it.
	<-arrived
	header := http.Header{"A": {"1"}, "B": {"2"}}
	var wg sync.WaitGroup
	for _, list := range [][]string{{"a", "b"}, {"b", "a"}} {
		wg.Go(func() {
			ctx := order.WithOrder(context.Background(), order.Order{Header: list})
			if err := sendCtx(t, tr, ctx, http.MethodGet, "https://example.com/"+list[0], header, ""); err != nil {
				t.Error(err)
			}
		})
	}
	<-arrived
	<-arrived
	close(release)
	wg.Wait()
	if err := <-warmErr; err != nil {
		t.Fatal(err)
	}
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
	seen := 0
	for _, fields := range h2Streams(t, srv.NextConn(t)) {
		var path string
		var regular []string
		for _, f := range fields {
			if strings.HasPrefix(f, ":path: ") {
				path = strings.TrimPrefix(f, ":path: ")
			} else if !strings.HasPrefix(f, ":") {
				regular = append(regular, f)
			}
		}
		switch path {
		case "/a":
			seen++
			if !slices.Equal(regular, []string{"a: 1", "b: 2"}) {
				t.Errorf("/a sent %q", regular)
			}
		case "/b":
			seen++
			if !slices.Equal(regular, []string{"b: 2", "a: 1"}) {
				t.Errorf("/b sent %q", regular)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("saw %d of the 2 requests", seen)
	}
}

// exactFields is a captured request with a repeated name between others
// and names in their own spelling.
var exactFields = []order.Field{
	{Name: "Host", Value: "example.com"},
	{Name: "Connection", Value: "keep-alive"},
	{Name: "cookie", Value: "a=1; c=3"},
	{Name: "Accept", Value: "*/*"},
	{Name: "cookie", Value: "b=2"},
	{Name: "X-Mixed", Value: "1"},
	{Name: "x-mixed", Value: "2"},
}

// Exact mode sends the fields as given and nothing else: Request.Header,
// the spelling table and the engines add nothing.
func TestExactHeaders(t *testing.T) {
	junk := http.Header{"User-Agent": {"from-header"}, "Cookie": {"jar=1"}}
	ctx := order.WithExact(context.Background(), exactFields)
	t.Run("http/1.1", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
		tr := transport(srv)
		defer tr.Close()
		if err := sendCtx(t, tr, ctx, http.MethodGet, "https://example.com/", junk, ""); err != nil {
			t.Fatal(err)
		}
		want := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\ncookie: a=1; c=3\r\nAccept: */*\r\ncookie: b=2\r\nX-Mixed: 1\r\nx-mixed: 2\r\n\r\n"
		if got := string(srv.NextConn(t).Bytes()); got != want {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})
	t.Run("h2", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{})
		tr := transport(srv)
		tr.Order = &order.Order{Pseudo: []string{":method", ":authority", ":scheme", ":path"}}
		defer tr.Close()
		if err := sendCtx(t, tr, ctx, http.MethodGet, "https://example.com/", junk, ""); err != nil {
			t.Fatal(err)
		}
		// Host becomes :authority, Connection is left out, Cookie is
		// not split.
		want := []string{":method: GET", ":authority: example.com", ":scheme: https", ":path: /",
			"cookie: a=1; c=3", "accept: */*", "cookie: b=2", "x-mixed: 1", "x-mixed: 2"}
		if got := h2Streams(t, srv.NextConn(t))[1]; !slices.Equal(got, want) {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})
}

// With a body, the framing comes from the fields and must match it.
func TestExactHeadersBody(t *testing.T) {
	fields := []order.Field{{Name: "Host", Value: "example.com"}, {Name: "Content-Length", Value: "7"}, {Name: "Content-Type", Value: "text/plain"}}
	ctx := order.WithExact(context.Background(), fields)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) != "payload" {
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	for _, protos := range [][]string{{"http/1.1"}, {"h2"}} {
		t.Run(protos[0], func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: echo})
			tr := transport(srv)
			defer tr.Close()
			if err := sendCtx(t, tr, ctx, http.MethodPost, "https://example.com/", nil, "payload"); err != nil {
				t.Fatal(err)
			}
		})
	}
	// HTTP/2 frames the body by itself: without a Content-Length field none
	// is added.
	t.Run("h2 without Content-Length", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{Handler: echo})
		tr := transport(srv)
		tr.Order = &order.Order{Pseudo: []string{":method", ":authority", ":scheme", ":path"}}
		defer tr.Close()
		ctx := order.WithExact(context.Background(), []order.Field{{Name: "Content-Type", Value: "text/plain"}})
		if err := sendCtx(t, tr, ctx, http.MethodPost, "https://example.com/", nil, "payload"); err != nil {
			t.Fatal(err)
		}
		want := []string{":method: POST", ":authority: example.com", ":scheme: https", ":path: /", "content-type: text/plain"}
		if got := h2Streams(t, srv.NextConn(t))[1]; !slices.Equal(got, want) {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})
}

// Incoherent framing is refused before anything is sent, never corrected.
func TestExactHeadersRefused(t *testing.T) {
	tests := []struct {
		name   string
		protos []string
		fields []order.Field
		body   string
	}{
		{"h1 without Host", []string{"http/1.1"}, []order.Field{{Name: "Accept", Value: "*/*"}}, ""},
		{"h1 with two Hosts", []string{"http/1.1"}, []order.Field{{Name: "Host", Value: "a"}, {Name: "Host", Value: "b"}}, ""},
		{"h1 body without Content-Length", []string{"http/1.1"}, []order.Field{{Name: "Host", Value: "example.com"}}, "payload"},
		{"h1 wrong Content-Length", []string{"http/1.1"}, []order.Field{{Name: "Host", Value: "example.com"}, {Name: "Content-Length", Value: "3"}}, "payload"},
		{"h1 Content-Length with a sign", []string{"http/1.1"}, []order.Field{{Name: "Host", Value: "example.com"}, {Name: "Content-Length", Value: "+7"}}, "payload"},
		{"h2 Content-Length with a sign", []string{"h2"}, []order.Field{{Name: "Content-Length", Value: "+7"}}, "payload"},
		{"h1 Transfer-Encoding", []string{"http/1.1"}, []order.Field{{Name: "Host", Value: "example.com"}, {Name: "Transfer-Encoding", Value: "chunked"}}, ""},
		{"h1 CRLF in value", []string{"http/1.1"}, []order.Field{{Name: "Host", Value: "example.com"}, {Name: "X-A", Value: "1\r\nX-B: 2"}}, ""},
		{"h2 wrong Content-Length", []string{"h2"}, []order.Field{{Name: "Content-Length", Value: "3"}}, "payload"},
		{"h2 invalid name", []string{"h2"}, []order.Field{{Name: "X A", Value: "1"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var handled atomic.Int32
			srv := lab.Start(t, lab.Options{NextProtos: tt.protos, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				handled.Add(1)
			})})
			tr := transport(srv)
			defer tr.Close()
			ctx := order.WithExact(context.Background(), tt.fields)
			method := http.MethodGet
			if tt.body != "" {
				method = http.MethodPost
			}
			if err := sendCtx(t, tr, ctx, method, "https://example.com/", nil, tt.body); err == nil {
				t.Fatal("no error")
			}
			if n := handled.Load(); n != 0 {
				t.Fatalf("the server handled %d requests", n)
			}
		})
	}
}

// A replay after a lost idle connection sends the same exact fields on the
// new connection.
func TestExactHeadersKeptOnReplay(t *testing.T) {
	var n atomic.Int32
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 2 {
			hijack(w, "", true)
			return
		}
		io.WriteString(w, "ok")
	})})
	tr := transport(srv)
	defer tr.Close()
	fetch(t, tr, "https://example.com/warm")
	ctx := order.WithExact(context.Background(), exactFields)
	if err := sendCtx(t, tr, ctx, http.MethodGet, "https://example.com/", nil, ""); err != nil {
		t.Fatal(err)
	}
	srv.NextConn(t)
	want := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\ncookie: a=1; c=3\r\nAccept: */*\r\ncookie: b=2\r\nX-Mixed: 1\r\nx-mixed: 2\r\n\r\n"
	if got := string(srv.NextConn(t).Bytes()); got != want {
		t.Fatalf("replay sent %q\nwant %q", got, want)
	}
}

// A redirect of a request in exact mode fails before sending anything.
func TestExactHeadersRedirect(t *testing.T) {
	var paths []string
	var mu sync.Mutex
	srv := lab.Start(t, lab.Options{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		http.Redirect(w, r, "/next", http.StatusFound)
	})})
	tr := transport(srv)
	defer tr.Close()
	client := &http.Client{Transport: tr}
	ctx := order.WithExact(context.Background(), exactFields)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/start", nil)
	if _, err := client.Do(req); !errors.Is(err, dispatch.ErrExactHeadersRedirect) {
		t.Fatalf("err = %v, want ErrExactHeadersRedirect", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(paths, []string{"/start"}) {
		t.Fatalf("server saw %v", paths)
	}
}
