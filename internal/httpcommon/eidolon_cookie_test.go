package httpcommon

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// Cookie is split as Chrome splits it (quiche CookieToCrumbs).
func TestCookieCrumbs(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want []string
	}{
		{"a=1", []string{"a=1"}},
		{"a=1; b=2", []string{"a=1", "b=2"}},
		{"a=1;b=2", []string{"a=1", "b=2"}},
		{" \ta=1; b=2 \t", []string{"a=1", "b=2"}},
		{"a=1;  b=2", []string{"a=1", " b=2"}},
		{"a=1 ; b=2", []string{"a=1 ", "b=2"}},
		{"a=1;\tb=2", []string{"a=1", "\tb=2"}},
		{"a=1;;b=2", []string{"a=1", "", "b=2"}},
		{"a=1;", []string{"a=1", ""}},
		{"a=1; ", []string{"a=1", ""}},
		{"", []string{""}},
		{" ", []string{""}},
	} {
		if got := cookieCrumbs(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("cookieCrumbs(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Every Cookie field sent is free of whitespace at its ends (RFC 9113
// section 8.2.1): a crumb that is not is refused, and in exact mode, where
// Cookie is not split, so is the whole value.
func TestCookieEdges(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
		exact bool
		want  []string // nil: refused
	}{
		{"trimmed", " a=1; b=2 ", false, []string{"a=1", "b=2"}},
		{"empty crumbs", "a=1;;b=2;", false, []string{"a=1", "", "b=2", ""}},
		{"space before ';'", "a=1 ;b=2", false, nil},
		{"tab after ';'", "a=1;\tb=2", false, nil},
		{"two spaces after ';'", "a=1;  b=2", false, nil},
		{"exact", "a=1; b=2", true, []string{"a=1; b=2"}},
		{"exact trailing space", "a=1; b=2 ", true, nil},
		{"exact leading tab", "\ta=1", true, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Host: "example.com", Path: "/"}, Header: http.Header{}}
			ctx := context.Background()
			if tt.exact {
				ctx = order.WithExact(ctx, []order.Field{{Name: "cookie", Value: tt.value}})
			} else {
				req.Header.Set("Cookie", tt.value)
			}
			var got []string
			_, err := EncodeHeaders(ctx, EncodeHeadersParam{Request: Request{
				Header: req.Header, URL: req.URL, Method: req.Method, ActualContentLength: 0,
			}}, func(name, value string) {
				if name == "cookie" {
					got = append(got, value)
				}
			})
			if tt.want == nil {
				if err == nil {
					t.Fatalf("sent %q", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("cookie fields %q, want %q", got, tt.want)
			}
		})
	}
}
