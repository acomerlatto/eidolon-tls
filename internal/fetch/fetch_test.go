package fetch

import (
	"context"
	"net/http"
	"slices"
	"testing"
)

func TestKnown(t *testing.T) {
	if !slices.IsSorted(dests) {
		t.Fatal("dests is not sorted")
	}
	for _, d := range dests {
		if !Known(d) {
			t.Errorf("Known(%q) = false", d)
		}
	}
	for _, d := range []string{"", "Document", "navigate", "xhr", "fetch"} {
		if Known(d) {
			t.Errorf("Known(%q) = true", d)
		}
	}
}

func TestDest(t *testing.T) {
	const navAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
	for _, tt := range []struct {
		name   string
		ctx    string // "" for none
		method string
		header http.Header
		want   string
	}{
		{"context", "style", "POST", http.Header{"Sec-Fetch-Dest": {"image"}, "Content-Type": {"application/json"}}, "style"},
		{"context over GET", "empty", "GET", nil, "empty"},
		{"context not captured", "font", "GET", nil, "font"},
		{"header dest", "", "GET", http.Header{"Sec-Fetch-Dest": {"Script"}}, "script"},
		{"header dest unknown", "", "GET", http.Header{"Sec-Fetch-Dest": {"xhr"}}, "document"},
		{"header dest over mode", "", "GET", http.Header{"Sec-Fetch-Dest": {"image"}, "Sec-Fetch-Mode": {"navigate"}}, "image"},
		{"mode navigate", "", "POST", http.Header{"Sec-Fetch-Mode": {"Navigate"}, "Content-Type": {"application/json"}}, "document"},
		{"mode cors", "", "GET", http.Header{"Sec-Fetch-Mode": {"cors"}}, "empty"},
		{"mode no-cors", "", "GET", http.Header{"Sec-Fetch-Mode": {"no-cors"}, "Accept": {navAccept}}, "empty"},
		{"accept json", "", "GET", http.Header{"Accept": {"application/json"}}, "empty"},
		{"accept bare any", "", "GET", http.Header{"Accept": {" */* "}}, "empty"},
		{"accept problem json", "", "GET", http.Header{"Accept": {"application/problem+json; q=0.9"}}, "empty"},
		{"accept xml", "", "HEAD", http.Header{"Accept": {"application/xml"}}, "empty"},
		{"accept atom", "", "GET", http.Header{"Accept": {"application/atom+xml"}}, "empty"},
		{"accept text", "", "GET", http.Header{"Accept": {"text/plain"}}, "empty"},
		{"accept octets", "", "GET", http.Header{"Accept": {"application/octet-stream"}}, "empty"},
		{"accept navigation", "", "GET", http.Header{"Accept": {navAccept}}, "document"},
		{"accept html after json", "", "GET", http.Header{"Accept": {"application/json, TEXT/HTML"}}, "document"},
		{"accept xhtml", "", "GET", http.Header{"Accept": {"application/xhtml+xml, application/json"}}, "document"},
		{"accept image", "", "GET", http.Header{"Accept": {"image/webp,*/*"}}, "document"},
		{"GET", "", "GET", nil, "document"},
		{"no method", "", "", nil, "document"},
		{"HEAD", "", "HEAD", nil, "document"},
		{"POST form", "", "POST", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, "document"},
		{"POST multipart", "", "POST", http.Header{"Content-Type": {"Multipart/Form-Data; boundary=x"}}, "document"},
		{"POST json", "", "POST", http.Header{"Content-Type": {"application/json"}}, "empty"},
		{"POST text", "", "POST", http.Header{"Content-Type": {"text/plain"}}, "empty"},
		{"POST no type", "", "POST", nil, "empty"},
		{"PUT form", "", "PUT", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, "empty"},
		{"DELETE", "", "DELETE", nil, "empty"},
		{"OPTIONS", "", "OPTIONS", nil, "empty"},
		{"lowercase get", "", "get", nil, "empty"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.ctx != "" {
				ctx = WithDest(ctx, tt.ctx)
			}
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/", nil)
			req.Method = tt.method
			if tt.header != nil {
				req.Header = tt.header
			}
			got, err := Dest(req)
			if err != nil || got != tt.want {
				t.Fatalf("Dest = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

// A destination in the context that Sec-Fetch-Dest cannot send is an
// error, not inferred over.
func TestDestUnknown(t *testing.T) {
	for _, d := range []string{"", "xhr", "Document"} {
		req, _ := http.NewRequestWithContext(WithDest(context.Background(), d), "GET", "https://example.com/", nil)
		if got, err := Dest(req); err == nil {
			t.Errorf("Dest with %q = %q, want an error", d, got)
		}
	}
	if _, ok := DestFromContext(context.Background()); ok {
		t.Error("a destination in an empty context")
	}
}
