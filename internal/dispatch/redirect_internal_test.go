package dispatch

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

// chain returns the request of the last of urls, linked through
// Response.Request to the ones before it, the first with header h.
func chain(h http.Header, urls ...string) *http.Request {
	var req *http.Request
	for i, s := range urls {
		u, _ := url.Parse(s)
		next := &http.Request{URL: u, Header: http.Header{}}
		if i == 0 {
			next.Header = h
		} else {
			next.Response = &http.Response{Request: req}
		}
		req = next
	}
	return req
}

func TestRedirectHeader(t *testing.T) {
	for _, tt := range []struct {
		name    string
		ref     string   // Referer of the first request
		urls    []string // the chain, the hop under test last
		referer string
		auth    bool
	}{
		{"same origin", "https://u:p@Example.com:443/a/b?q=1#f",
			[]string{"https://example.com/a/b", "https://example.com/c"}, "https://example.com/a/b?q=1", true},
		{"referrer cross origin", "https://example.com/a?q=1",
			[]string{"https://example.com/a", "https://other.test/"}, "https://example.com/", false},
		{"referrer of the next origin", "https://other.test/p?q=1",
			[]string{"https://example.com/a", "https://other.test/"}, "https://other.test/p?q=1", false},
		{"cross scheme", "http://example.com/a",
			[]string{"http://example.com/a", "https://example.com/"}, "http://example.com/", false},
		{"port kept", "https://example.com:8443/a",
			[]string{"https://example.com:8443/a", "https://other.test/"}, "https://example.com:8443/", false},
		{"ipv6", "https://[::1]:8443/a",
			[]string{"https://[::1]:8443/a", "https://[::1]:8443/b"}, "https://[::1]:8443/a", true},
		{"ipv6 cross", "https://[::1]/a",
			[]string{"https://[::1]/a", "https://example.com/"}, "https://[::1]/", false},
		{"downgrade", "https://example.com/a",
			[]string{"https://example.com/a", "http://example.com/a"}, "", false},
		{"downgrade of the hop only", "http://caller.test/",
			[]string{"https://example.com/a", "http://example.com/a"}, "http://caller.test/", false},
		{"IDN", "https://bücher.example/a?q=1",
			[]string{"https://bücher.example/a", "https://xn--bcher-kva.example/b"}, "https://xn--bcher-kva.example/a?q=1", true},
		{"IDN cross", "https://bücher.example/a",
			[]string{"https://bücher.example/a", "https://other.test/"}, "https://xn--bcher-kva.example/", false},
		{"not http", "ftp://example.com/a",
			[]string{"https://example.com/a", "https://example.com/"}, "", true},
		{"no referrer", "",
			[]string{"https://example.com/a", "https://example.com/b"}, "", true},
		{"origin only", "https://example.com",
			[]string{"https://example.com/a", "https://example.com/b"}, "https://example.com/", true},
		// Credentials do not come back once a hop changed origin.
		{"back to the origin", "https://example.com/a",
			[]string{"https://example.com/a", "https://other.test/", "https://example.com/b"}, "https://example.com/a", false},
		{"cross then same", "",
			[]string{"https://example.com/a", "https://other.test/", "https://other.test/b"}, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			first := http.Header{"Authorization": {"a"}, "Proxy-Authorization": {"p"}}
			if tt.ref != "" {
				first.Set("Referer", tt.ref)
			}
			req := chain(first, tt.urls...)
			h := http.Header{"Referer": {"https://caller.test/"}, "Authorization": {"a"}, "Proxy-Authorization": {"p"}, "X-A": {"1"}}
			before := h.Clone()
			got := redirectHeader(req, h)
			if !reflect.DeepEqual(h, before) {
				t.Fatalf("h changed: %v", h)
			}
			if ref := got.Get("Referer"); ref != tt.referer {
				t.Errorf("Referer = %q, want %q", ref, tt.referer)
			}
			if _, ok := got["Referer"]; ok != (tt.referer != "") {
				t.Errorf("Referer present = %v", ok)
			}
			for _, k := range []string{"Authorization", "Proxy-Authorization"} {
				if _, ok := got[k]; ok != tt.auth {
					t.Errorf("%s kept = %v, want %v", k, ok, tt.auth)
				}
			}
			if got.Get("X-A") != "1" {
				t.Error("X-A lost")
			}
		})
	}
	// A request that is not a redirect keeps its header, Referer included.
	h := http.Header{"Referer": {"https://caller.test/"}}
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}
	if got := redirectHeader(req, h); !reflect.DeepEqual(got, h) {
		t.Fatalf("got %v", got)
	}
}
