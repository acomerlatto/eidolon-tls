package dispatch_test

import (
	"net/http"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// Header fields HTTP/2 forbids are refused before any HEADERS frame: TE
// other than "trailers" (RFC 9113 section 8.2.2) and values with leading or
// trailing whitespace (section 8.2.1).
func TestH2RefusesInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		ok     bool
	}{
		{name: "TE trailers", header: http.Header{"Te": {"trailers"}}, ok: true},
		{name: "TE trailers any case", header: http.Header{"Te": {"Trailers"}}, ok: true},
		{name: "TE gzip", header: http.Header{"Te": {"gzip"}}},
		{name: "TE trailers and gzip", header: http.Header{"Te": {"trailers", "gzip"}}},
		{name: "TE non-canonical key", header: http.Header{"te": {"gzip"}}},
		{name: "leading space", header: http.Header{"X-A": {" a"}}},
		{name: "trailing tab", header: http.Header{"X-A": {"a\t"}}},
		{name: "inner space", header: http.Header{"X-A": {"a b"}}, ok: true},
		{name: "empty value", header: http.Header{"X-A": {""}}, ok: true},
		{name: "cookie with space after the last ';'", header: http.Header{"Cookie": {"a=b; "}}, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
			tr := transport(srv)
			defer tr.Close()
			req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
			req.Header = tt.header
			resp, err := tr.RoundTrip(req)
			if resp != nil {
				resp.Body.Close()
			}
			if tt.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("request sent")
			}
			// A valid request on the same pooled connection is the only
			// HEADERS frame: the refused one wrote nothing, not even to the
			// HPACK state.
			fetch(t, tr, "https://example.com/valid")
			if n := srv.Accepted(); n != 1 {
				t.Fatalf("%d connections, want 1", n)
			}
			if n := headersFrames(t, srv.NextConn(t)); n != 1 {
				t.Fatalf("%d HEADERS frames, want only the valid request's", n)
			}
		})
	}
}
