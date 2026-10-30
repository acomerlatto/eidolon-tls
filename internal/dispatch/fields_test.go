package dispatch_test

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/lab"
	"github.com/acomerlatto/eidolon-tls/internal/order"
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

// sentFields returns the fields of the first request of conn, lowercase,
// with their values: from its HEADERS frame over HTTP/2, from its head
// over HTTP/1.1.
func sentFields(t *testing.T, conn *lab.Conn) map[string]string {
	t.Helper()
	<-conn.Done()
	out := map[string]string{}
	if conn.State.NegotiatedProtocol == "h2" {
		frames, err := conn.H2Frames()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range frames {
			if f.Type == "HEADERS" {
				for _, h := range f.Headers {
					out[h.Name] = h.Value
				}
				return out
			}
		}
		t.Fatal("no HEADERS frame")
	}
	head, _, _ := strings.Cut(string(conn.Bytes()), "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n")[1:] {
		k, v, _ := strings.Cut(line, ": ")
		out[strings.ToLower(k)] = v
	}
	return out
}

// Without Headers, Priority goes over HTTP/2 only and H1Connection over
// HTTP/1.1 only, unless the request has the field or is exact.
func TestProtocolFields(t *testing.T) {
	tests := []struct {
		name          string
		header        http.Header
		exact         bool
		h2, h1        map[string]string // the values of priority and connection, "-" for none
		priority, con string
	}{
		{name: "added", header: http.Header{"X-A": {"1"}}, h2: map[string]string{"priority": "u=4, i", "connection": "-"}, h1: map[string]string{"priority": "-", "connection": "keep-alive"}},
		{name: "no header", h2: map[string]string{"priority": "u=4, i"}, h1: map[string]string{"connection": "keep-alive"}},
		{name: "caller's", header: http.Header{"Priority": {"u=0"}, "Connection": {"keep-alive"}}, priority: "u=4, i", con: "close", h2: map[string]string{"priority": "u=0"}, h1: map[string]string{"priority": "u=0", "connection": "keep-alive"}},
		{name: "removed", header: http.Header{"Priority": nil, "Connection": nil}, h2: map[string]string{"priority": "-"}, h1: map[string]string{"connection": "-"}},
		{name: "exact", exact: true, h2: map[string]string{"priority": "-"}, h1: map[string]string{"connection": "-"}},
		{name: "only priority", priority: "u=1", h2: map[string]string{"priority": "u=1"}, h1: map[string]string{"priority": "-", "connection": "-"}},
		{name: "only connection", con: "keep-alive", h2: map[string]string{"priority": "-"}, h1: map[string]string{"connection": "keep-alive"}},
	}
	for _, tt := range tests {
		for _, proto := range []string{"h2", "http/1.1"} {
			t.Run(tt.name+" "+proto, func(t *testing.T) {
				srv := lab.Start(t, lab.Options{NextProtos: []string{proto}})
				tr := transport(srv)
				tr.Priority, tr.H1Connection = "u=4, i", "keep-alive"
				if tt.priority != "" || tt.con != "" {
					tr.Priority, tr.H1Connection = tt.priority, tt.con
				}
				ctx := context.Background()
				if tt.exact {
					ctx = order.WithExact(ctx, []order.Field{{Name: "Host", Value: "example.com"}, {Name: "X-A", Value: "1"}})
				}
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
				req.Header = tt.header
				before := tt.header.Clone()
				resp, err := tr.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				tr.Close()
				if !reflect.DeepEqual(req.Header, before) {
					t.Errorf("request header changed to %v", req.Header)
				}
				got := sentFields(t, srv.NextConn(t))
				want := tt.h2
				if proto != "h2" {
					want = tt.h1
				}
				for k, v := range want {
					if g, ok := got[k]; v == "-" && ok || v != "-" && g != v {
						t.Errorf("%s: %q (present %v), want %q", k, g, ok, v)
					}
				}
			})
		}
	}
}
