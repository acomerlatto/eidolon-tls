package eidolon_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// hops records the headers of the requests a lab handler received, by
// path.
type hops struct {
	mu   sync.Mutex
	seen map[string]http.Header
}

func (h *hops) get(path string) http.Header {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.seen[path]
}

// redirector answers /from with a redirect to the "to" query value and
// records every request.
func redirector(h *hops) http.Handler {
	h.seen = map[string]http.Header{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.seen[r.URL.Path] = r.Header.Clone()
		h.mu.Unlock()
		if to := r.URL.Query().Get("to"); to != "" {
			http.Redirect(w, r, to, http.StatusFound)
		}
	})
}

// routedClient returns a client whose connections to port 80 go to plain
// and all others to srv.
func routedClient(t *testing.T, srv, plain *lab.Server, opts ...eidolon.Option) eidolon.HttpClient {
	t.Helper()
	base := []eidolon.Option{
		eidolon.WithClientHello(chromeSpec),
		eidolon.WithRootCAs(srv.RootCAs),
		eidolon.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			to := srv.Addr
			if strings.HasSuffix(addr, ":80") {
				to = plain.Addr
			}
			var d net.Dialer
			return d.DialContext(ctx, network, to)
		}),
	}
	c, err := eidolon.New(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func get(t *testing.T, do func(*http.Request) (*http.Response, error), url string, header http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// Referer and credentials at each redirect hop follow the Fetch standard:
// the Referer comes from the referrer of the first request under
// strict-origin-when-cross-origin, and Authorization is dropped across
// origins and from https to http.
func TestRedirectHeaders(t *testing.T) {
	var h hops
	srv := lab.Start(t, lab.Options{Handler: redirector(&h)})
	plain := lab.Start(t, lab.Options{Plain: true, Handler: redirector(&h)})
	c := routedClient(t, srv, plain)
	for _, tt := range []struct {
		name, ref, url, next string
		referer              string
		auth                 bool
	}{
		{"same origin", "https://example.com/page?q=1#frag", "https://example.com/from?to=/same1", "/same1",
			"https://example.com/page?q=1", true},
		{"default port", "https://example.com:443/page", "https://example.com:443/from?to=/same2", "/same2",
			"https://example.com/page", true},
		{"cross host", "https://example.com/page", "https://example.com/from?to=https://127.0.0.1/cross1", "/cross1",
			"https://example.com/", false},
		{"to the referrer origin", "https://127.0.0.1/page", "https://example.com/from?to=https://127.0.0.1/cross2", "/cross2",
			"https://127.0.0.1/page", false},
		{"cross port", "https://example.com/page", "https://example.com/from?to=https://example.com:8443/cross3", "/cross3",
			"https://example.com/", false},
		{"downgrade", "https://example.com/page", "https://example.com/from?to=http://example.com/down", "/down",
			"", false},
		{"upgrade", "http://example.com/page", "http://example.com/from?to=https://example.com/up", "/up",
			"http://example.com/", false},
		{"no referrer", "", "https://example.com/from?to=/same3", "/same3",
			"", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{"Authorization": {"Bearer t"}, "Proxy-Authorization": {"Basic p"}}
			if tt.ref != "" {
				header.Set("Referer", tt.ref)
			}
			get(t, c.Do, tt.url, header)
			got := h.get(tt.next)
			if got == nil {
				t.Fatalf("%s not reached", tt.next)
			}
			if ref := got.Get("Referer"); ref != tt.referer {
				t.Errorf("Referer = %q, want %q", ref, tt.referer)
			}
			for _, k := range []string{"Authorization", "Proxy-Authorization"} {
				if _, ok := got[k]; ok != tt.auth {
					t.Errorf("%s sent = %v, want %v", k, ok, tt.auth)
				}
			}
			// The first request keeps the Referer of the caller.
			if ref := h.get("/from").Get("Referer"); ref != tt.ref {
				t.Errorf("first Referer = %q, want %q", ref, tt.ref)
			}
		})
	}
}

// Credentials dropped at a hop that changed origin are not sent at a later
// hop within the new origin, through the client and through an
// http.Client built on Transport(). http.Client copies them again when
// the host is the first one or a subdomain of it.
func TestRedirectCredentialsStayDropped(t *testing.T) {
	var h hops
	cert, err := lab.NewCertificate(time.Hour, "example.com", "sub.example.com")
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{Certificate: &cert, Handler: redirector(&h)})
	plain := lab.Start(t, lab.Options{Plain: true, Handler: redirector(&h)})
	c := routedClient(t, srv, plain)
	for _, tt := range []struct {
		name string
		do   func(*http.Request) (*http.Response, error)
	}{
		{"client", c.Do},
		{"transport", (&http.Client{Transport: c.Transport()}).Do},
	} {
		for _, hops := range [][]string{
			{"http://example.com/away", "http://example.com/back"},
			{"https://sub.example.com/away", "https://sub.example.com/back"},
		} {
			t.Run(tt.name+" "+hops[0], func(t *testing.T) {
				h.mu.Lock()
				clear(h.seen)
				h.mu.Unlock()
				next := hops[0] + "?to=" + url.QueryEscape(hops[1])
				get(t, tt.do, "https://example.com/from?to="+url.QueryEscape(next), http.Header{"Authorization": {"Bearer t"}})
				for _, p := range []string{"/away", "/back"} {
					got := h.get(p)
					if got == nil {
						t.Fatalf("%s not reached", p)
					}
					if v, ok := got["Authorization"]; ok {
						t.Errorf("%s got Authorization %q", p, v)
					}
				}
			})
		}
	}
}

// An http.Client built on Transport() gets the same Referer.
func TestRedirectRefererTransport(t *testing.T) {
	var h hops
	srv := lab.Start(t, lab.Options{Handler: redirector(&h)})
	c := newClient(t, srv)
	hc := &http.Client{Transport: c.Transport()}
	get(t, hc.Do, "https://example.com/from?to=https://127.0.0.1/next", http.Header{"Referer": {"https://example.com/page"}})
	if ref := h.get("/next").Get("Referer"); ref != "https://example.com/" {
		t.Fatalf("Referer = %q", ref)
	}
	get(t, hc.Do, "https://example.com/from?to=/plain", nil)
	if ref, ok := h.get("/plain")["Referer"]; ok {
		t.Fatalf("Referer = %q without a referrer", ref)
	}
}

// The credentials of the URL are sent as Basic Authorization and nowhere
// else, and the Referer of the next hop leaves them out.
func TestURLCredentials(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/from" {
			http.Redirect(w, r, "/next", http.StatusFound)
		}
	})})
	c := newClient(t, srv)
	get(t, c.Do, "https://user:pass@example.com/from", http.Header{eidolon.HeaderOrderKey: {"host", "referer", "authorization"}, "Referer": {"https://user:pass@example.com/page#f"}})
	want := "GET /from HTTP/1.1\r\nHost: example.com\r\nReferer: https://user:pass@example.com/page#f\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n" +
		"GET /next HTTP/1.1\r\nHost: example.com\r\nReferer: https://example.com/page\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
	if got := string(srv.NextConn(t).Bytes()); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// The method and body at each hop are those of http.Client, which match
// httpcloak: 301, 302 and 303 turn a POST into a GET without body or
// Content-Type, and 307 and 308 send the same body again (GetBody).
func TestRedirectMethodAndBody(t *testing.T) {
	type hit struct{ method, ctype, body string }
	for _, tt := range []struct {
		code int
		want hit
	}{
		{http.StatusMovedPermanently, hit{"GET", "", ""}},
		{http.StatusFound, hit{"GET", "", ""}},
		{http.StatusSeeOther, hit{"GET", "", ""}},
		{http.StatusTemporaryRedirect, hit{"POST", "text/plain", "payload"}},
		{http.StatusPermanentRedirect, hit{"POST", "text/plain", "payload"}},
	} {
		for _, protos := range [][]string{{"http/1.1"}, {"h2"}} {
			t.Run(http.StatusText(tt.code)+"/"+protos[0], func(t *testing.T) {
				hits := make(chan hit, 1)
				srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/from" {
						io.Copy(io.Discard, r.Body)
						http.Redirect(w, r, "/next", tt.code)
						return
					}
					b, _ := io.ReadAll(r.Body)
					hits <- hit{r.Method, r.Header.Get("Content-Type"), string(b)}
				})})
				c := newClient(t, srv)
				resp, err := c.Post("https://example.com/from", "text/plain", strings.NewReader("payload"))
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if got := <-hits; got != tt.want {
					t.Fatalf("next hop got %+v, want %+v", got, tt.want)
				}
			})
		}
	}
}
