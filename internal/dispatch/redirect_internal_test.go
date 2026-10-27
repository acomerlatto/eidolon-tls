package dispatch

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestRedirectHeader(t *testing.T) {
	for _, tt := range []struct {
		name, prev, next string
		referer          string
		auth             bool
	}{
		{"same origin", "https://u:p@Example.com:443/a/b?q=1#f", "https://example.com/c", "https://example.com/a/b?q=1", true},
		{"cross origin", "https://example.com/a?q=1", "https://other.test/", "https://example.com/", false},
		{"cross scheme", "http://example.com/a", "https://example.com/", "http://example.com/", false},
		{"port kept", "https://example.com:8443/a", "https://other.test/", "https://example.com:8443/", false},
		{"ipv6", "https://[::1]:8443/a", "https://[::1]:8443/b", "https://[::1]:8443/a", true},
		{"ipv6 cross", "https://[::1]/a", "https://example.com/", "https://[::1]/", false},
		{"downgrade", "https://example.com/a", "http://example.com/a", "", false},
		{"not http", "ftp://example.com/a", "https://example.com/", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			prev, _ := url.Parse(tt.prev)
			next, _ := url.Parse(tt.next)
			h := http.Header{"Referer": {"https://caller.test/"}, "Authorization": {"a"}, "Proxy-Authorization": {"p"}, "X-A": {"1"}}
			before := h.Clone()
			req := &http.Request{URL: next, Response: &http.Response{Request: &http.Request{URL: prev}}}
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
