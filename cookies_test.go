package eidolon_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

func TestWithCookieJarNil(t *testing.T) {
	if c, err := eidolon.New(eidolon.WithClientHello(chromeSpec), eidolon.WithCookieJar(nil)); !errors.Is(err, eidolon.ErrConfig) || c != nil {
		t.Fatalf("New = %v, %v; want nil, ErrConfig", c, err)
	}
}

// cookieServer sets a=1 on /set, which redirects to /check, and b=2 on
// /check.
func cookieServer(t *testing.T, protos []string) *lab.Server {
	return lab.Start(t, lab.Options{NextProtos: protos, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			http.SetCookie(w, &http.Cookie{Name: "a", Value: "1", Path: "/"})
			http.Redirect(w, r, "/check", http.StatusFound)
		case "/check":
			http.SetCookie(w, &http.Cookie{Name: "b", Value: "2", Path: "/"})
		}
	})})
}

// The jar stores the Set-Cookie of a redirect response and adds its
// cookies after the caller's, in one Cookie field placed by the order.
func TestCookieJar(t *testing.T) {
	srv := cookieServer(t, []string{"http/1.1"})
	c := newClient(t, srv, eidolon.WithCookieJar(eidolon.NewCookieJar()))
	get(t, c.Do, "https://example.com/set", http.Header{
		"Cookie":               {"c=0"},
		"X-A":                  {"1"},
		eidolon.HeaderOrderKey: {"host", "cookie", "x-a"},
	})
	want := "GET /set HTTP/1.1\r\nHost: example.com\r\nCookie: c=0\r\nX-A: 1\r\n\r\n" +
		"GET /check HTTP/1.1\r\nHost: example.com\r\nCookie: c=0; a=1\r\nX-A: 1\r\n\r\n"
	if got := string(srv.NextConn(t).Bytes()); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	u, _ := url.Parse("https://example.com/")
	var names []string
	for _, ck := range c.GetCookies(u) {
		names = append(names, ck.Name+"="+ck.Value)
	}
	if len(names) != 2 || names[0] != "a=1" || names[1] != "b=2" {
		t.Fatalf("GetCookies = %v", names)
	}
}

// SetCookies feeds the jar; the public suffix list keeps a cookie from
// covering a whole suffix.
func TestSetCookies(t *testing.T) {
	srv := cookieServer(t, nil)
	c := newClient(t, srv, eidolon.WithCookieJar(eidolon.NewCookieJar()))
	u, _ := url.Parse("https://example.com/")
	c.SetCookies(u, []*http.Cookie{{Name: "s", Value: "1"}})
	sub, _ := url.Parse("https://a.co.uk/")
	c.SetCookies(sub, []*http.Cookie{{Name: "wide", Value: "1", Domain: "co.uk"}})
	if got := c.GetCookies(&url.URL{Scheme: "https", Host: "b.co.uk", Path: "/"}); len(got) != 0 {
		t.Fatalf("cookie for a public suffix stored: %v", got)
	}
	var h hops
	srv2 := lab.Start(t, lab.Options{Handler: redirector(&h)})
	c2 := newClient(t, srv2, eidolon.WithCookieJar(eidolon.NewCookieJar()))
	c2.SetCookies(u, []*http.Cookie{{Name: "s", Value: "1"}})
	get(t, c2.Do, "https://example.com/x", nil)
	if got := h.get("/x").Get("Cookie"); got != "s=1" {
		t.Fatalf("Cookie = %q", got)
	}
}

// Without a jar no cookie is stored or sent.
func TestNoCookieJar(t *testing.T) {
	srv := cookieServer(t, []string{"http/1.1"})
	c := newClient(t, srv)
	get(t, c.Do, "https://example.com/set", nil)
	u, _ := url.Parse("https://example.com/")
	c.SetCookies(u, []*http.Cookie{{Name: "s", Value: "1"}})
	if got := c.GetCookies(u); got != nil {
		t.Fatalf("GetCookies = %v", got)
	}
	want := "GET /set HTTP/1.1\r\nHost: example.com\r\n\r\nGET /check HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if got := string(srv.NextConn(t).Bytes()); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// In exact mode the cookies of the jar are not sent, over either protocol.
func TestCookieJarExactHeaders(t *testing.T) {
	for _, protos := range [][]string{{"http/1.1"}, {"h2"}} {
		t.Run(protos[0], func(t *testing.T) {
			var h hops
			srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: redirector(&h)})
			c := newClient(t, srv, eidolon.WithCookieJar(eidolon.NewCookieJar()))
			u, _ := url.Parse("https://example.com/")
			c.SetCookies(u, []*http.Cookie{{Name: "jar", Value: "1"}})
			ctx := eidolon.WithExactHeaders(context.Background(),
				eidolon.HeaderField{Name: "Host", Value: "example.com"},
				eidolon.HeaderField{Name: "Cookie", Value: "mine=1"})
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/x", nil)
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if got := h.get("/x")["Cookie"]; len(got) != 1 || got[0] != "mine=1" {
				t.Fatalf("Cookie = %q", got)
			}
		})
	}
}

// Each redirect hop sends the cookies the jar holds then, once, whatever
// the earlier hops sent: a cookie set, changed or removed by a redirect
// response shows at the next hop, and a cookie of the caller that a
// redirect response sets again leaves the caller's field for the jar. The
// caller's request is not modified.
func TestCookieJarRedirectHops(t *testing.T) {
	for _, tt := range []struct {
		name   string
		caller string
		set    *http.Cookie // set by /b
		want   []string     // Cookie at /a, /b and /c
	}{
		{"kept", "", nil, []string{"", "s=1", "s=1"}},
		{"changed", "", &http.Cookie{Name: "s", Value: "2", Path: "/"}, []string{"", "s=1", "s=2"}},
		{"removed", "", &http.Cookie{Name: "s", Path: "/", MaxAge: -1}, []string{"", "s=1", ""}},
		{"caller kept", "k=0", nil, []string{"k=0", "k=0; s=1", "k=0; s=1"}},
		{"caller replaced", "k=0; c=0", &http.Cookie{Name: "c", Value: "9", Path: "/"}, []string{"k=0; c=0", "k=0; c=0; s=1", "k=0; s=1; c=9"}},
	} {
		for _, protos := range [][]string{{"http/1.1"}, {"h2"}} {
			t.Run(tt.name+" "+protos[0], func(t *testing.T) {
				var mu sync.Mutex
				seen := map[string]string{}
				srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					seen[r.URL.Path] = strings.Join(r.Header.Values("Cookie"), " | ")
					mu.Unlock()
					switch r.URL.Path {
					case "/a":
						http.SetCookie(w, &http.Cookie{Name: "s", Value: "1", Path: "/"})
						http.Redirect(w, r, "/b", http.StatusFound)
					case "/b":
						if tt.set != nil {
							http.SetCookie(w, tt.set)
						}
						http.Redirect(w, r, "/c", http.StatusFound)
					}
				})})
				c := newClient(t, srv, eidolon.WithCookieJar(eidolon.NewCookieJar()))
				req, err := http.NewRequest(http.MethodGet, "https://example.com/a", nil)
				if err != nil {
					t.Fatal(err)
				}
				if tt.caller != "" {
					req.Header.Set("Cookie", tt.caller)
				}
				before := req.Header.Clone()
				resp, err := c.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				mu.Lock()
				defer mu.Unlock()
				for i, p := range []string{"/a", "/b", "/c"} {
					if seen[p] != tt.want[i] {
						t.Errorf("%s Cookie = %q, want %q", p, seen[p], tt.want[i])
					}
				}
				if !reflect.DeepEqual(req.Header, before) {
					t.Errorf("caller's header changed: %v, was %v", req.Header, before)
				}
			})
		}
	}
}
