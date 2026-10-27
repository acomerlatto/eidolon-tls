package dispatch_test

import (
	"bufio"
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// Without an order in the context, both engines send the regular headers in
// alphabetical order, never in map iteration order; two keys of the same
// name in different case are merged in byte order of the keys ("X-A"
// before "x-a"), each keeping the order of its values.
func TestDefaultHeaderOrderIsDeterministic(t *testing.T) {
	const runs = 20
	newReq := func() *http.Request {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.Header = http.Header{
			"Zeta":  {"z"},
			"Alpha": {"a"},
			"Mid":   {"m1", "m2"},
			"x-a":   {"3"},
			"X-A":   {"1", "2"},
		}
		return req
	}

	t.Run("h2", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
		tr := transport(srv)
		defer tr.Close()
		for range runs {
			resp, err := tr.RoundTrip(newReq())
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		frames, err := srv.NextConn(t).H2Frames()
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"alpha: a", "mid: m1", "mid: m2", "x-a: 1", "x-a: 2", "x-a: 3", "zeta: z"}
		n := 0
		for _, f := range frames {
			if f.Type != "HEADERS" {
				continue
			}
			n++
			var got []string
			for _, h := range f.Headers {
				if !strings.HasPrefix(h.Name, ":") {
					got = append(got, h.Name+": "+h.Value)
				}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("request %d: %q, want %q", n, got, want)
			}
		}
		if n != runs {
			t.Fatalf("%d HEADERS frames, want %d", n, runs)
		}
	})

	t.Run("http/1.1", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
		tr := transport(srv)
		defer tr.Close()
		want := []string{"Host: example.com", "Alpha: a", "Mid: m1", "Mid: m2", "X-A: 1", "X-A: 2", "X-A: 3", "Zeta: z"}
		for i := range runs {
			resp, err := tr.RoundTrip(newReq())
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			var got []string
			sc := bufio.NewScanner(bytes.NewReader(srv.NextConn(t).Bytes()))
			sc.Scan()
			for sc.Scan() && sc.Text() != "" {
				got = append(got, sc.Text())
			}
			if !slices.Equal(got, want) {
				t.Fatalf("request %d: %q, want %q", i, got, want)
			}
		}
	})
}
