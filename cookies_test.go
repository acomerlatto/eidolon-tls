package eidolon_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
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
		"GET /check HTTP/1.1\r\nHost: example.com\r\nCookie: c=0; a=1\r\nX-A: 1\r\nReferer: https://example.com/set\r\n\r\n"
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
	want := "GET /set HTTP/1.1\r\nHost: example.com\r\n\r\nGET /check HTTP/1.1\r\nHost: example.com\r\nReferer: https://example.com/set\r\n\r\n"
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
