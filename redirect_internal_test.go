package eidolon

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

// dropSetCookies removes the cookies set again from each Cookie field, keeps
// the order of the others and drops a field left empty.
func TestDropSetCookies(t *testing.T) {
	set := []*http.Cookie{{Name: "c"}, {Name: "d"}}
	for _, tt := range []struct {
		in, want http.Header
	}{
		{http.Header{"Cookie": {"k=0; c=0;", "d=1"}}, http.Header{"Cookie": {"k=0"}}},
		{http.Header{"cookie": {"c=0", "d=1"}, "X-A": {"c=0"}}, http.Header{"X-A": {"c=0"}}},
		{http.Header{"Cookie": {"b=1 ; c = 2; a=3"}}, http.Header{"Cookie": {"b=1; a=3"}}},
	} {
		h := tt.in.Clone()
		dropSetCookies(h, set)
		if !reflect.DeepEqual(h, tt.want) {
			t.Errorf("dropSetCookies(%v) = %v, want %v", tt.in, h, tt.want)
		}
	}
}

// Origins compare by their hosts as the URL standard serializes them: IDN
// in punycode, IP addresses in canonical form.
func TestSameOrigin(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"https://example.com/", "https://EXAMPLE.com:443/x", true},
		{"https://bücher.example/", "https://xn--bcher-kva.example/", true},
		{"https://[0:0::1]/", "https://[::1]/", true},
		{"https://0x7f.1/", "https://127.0.0.1/", true},
		{"https://example.com/", "https://example.org/", false},
		{"https://example.com/", "http://example.com/", false},
		{"https://example.com/", "https://example.com:8443/", false},
		{"https://example.com:0443/", "https://example.com/", true},
		{"http://example.com:0080/", "http://example.com:80/", true},
		{"https://example.com:08443/", "https://example.com:8443/", true},
	} {
		a, _ := url.Parse(tt.a)
		b, _ := url.Parse(tt.b)
		if got := sameOrigin(a, b); got != tt.want {
			t.Errorf("sameOrigin(%s, %s) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
