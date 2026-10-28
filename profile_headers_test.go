package eidolon_test

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// h2Fields returns the fields of the first HEADERS that c received.
func h2Fields(t *testing.T, c *lab.Conn) []lab.HeaderField {
	t.Helper()
	frames, err := c.H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if f.Type == "HEADERS" {
			return f.Headers
		}
	}
	t.Fatal("no HEADERS frame")
	return nil
}

// sendWith sends req through a client of srv with the Chrome profile and
// opts, and reads the response.
func sendWith(t *testing.T, srv *lab.Server, req *http.Request, opts ...eidolon.Option) error {
	t.Helper()
	c := profileClient(t, srv, append([]eidolon.Option{eidolon.WithProfile(eidolon.Chrome156Linux())}, opts...)...)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

const (
	chromeUA      = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
	chromeHints   = `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`
	chromeNavAcc  = "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	chromeImgAcc  = "image/jxl,image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
	chromeEncAll  = "gzip, deflate, br, zstd"
	chromeLang    = "en-US,en;q=0.9"
	chromeRequest = "https://example.com/"
)

// Over HTTP/2 each destination sends the fields and the order of the
// capture (A10 section 4), Sec-Fetch-Site and Origin aside (part 4).
func TestProfileHeadersH2(t *testing.T) {
	ctxDest := func(d eidolon.FetchDest) context.Context { return eidolon.WithFetchDest(context.Background(), d) }
	for _, tt := range []struct {
		name   string
		method string
		ctx    context.Context
		header http.Header
		body   string
		want   []lab.HeaderField
	}{
		{"navigation", "GET", context.Background(), nil, "", []lab.HeaderField{
			{Name: "sec-ch-ua", Value: chromeHints}, {Name: "sec-ch-ua-mobile", Value: "?0"}, {Name: "sec-ch-ua-platform", Value: `"Linux"`},
			{Name: "upgrade-insecure-requests", Value: "1"}, {Name: "user-agent", Value: chromeUA}, {Name: "accept", Value: chromeNavAcc},
			{Name: "sec-fetch-site", Value: "none"}, {Name: "sec-fetch-mode", Value: "navigate"}, {Name: "sec-fetch-user", Value: "?1"},
			{Name: "sec-fetch-dest", Value: "document"}, {Name: "accept-encoding", Value: chromeEncAll}, {Name: "accept-language", Value: chromeLang},
			{Name: "priority", Value: "u=0, i"},
		}},
		{"style", "GET", ctxDest(eidolon.FetchStyle), http.Header{"Referer": {chromeRequest}, "Cookie": {"lab=1"}}, "", []lab.HeaderField{
			{Name: "sec-ch-ua-platform", Value: `"Linux"`}, {Name: "user-agent", Value: chromeUA}, {Name: "sec-ch-ua", Value: chromeHints},
			{Name: "sec-ch-ua-mobile", Value: "?0"}, {Name: "accept", Value: "text/css,*/*;q=0.1"},
			{Name: "sec-fetch-site", Value: "same-origin"}, {Name: "sec-fetch-mode", Value: "no-cors"}, {Name: "sec-fetch-dest", Value: "style"},
			{Name: "referer", Value: chromeRequest}, {Name: "accept-encoding", Value: chromeEncAll}, {Name: "accept-language", Value: chromeLang},
			{Name: "cookie", Value: "lab=1"}, {Name: "priority", Value: "u=0"},
		}},
		{"image", "GET", ctxDest(eidolon.FetchImage), nil, "", []lab.HeaderField{
			{Name: "sec-ch-ua-platform", Value: `"Linux"`}, {Name: "user-agent", Value: chromeUA}, {Name: "sec-ch-ua", Value: chromeHints},
			{Name: "sec-ch-ua-mobile", Value: "?0"}, {Name: "accept", Value: chromeImgAcc},
			{Name: "sec-fetch-site", Value: "same-origin"}, {Name: "sec-fetch-mode", Value: "no-cors"}, {Name: "sec-fetch-dest", Value: "image"},
			{Name: "accept-encoding", Value: chromeEncAll}, {Name: "accept-language", Value: chromeLang}, {Name: "priority", Value: "u=2, i"},
		}},
		{"script", "GET", ctxDest(eidolon.FetchScript), nil, "", []lab.HeaderField{
			{Name: "sec-ch-ua-platform", Value: `"Linux"`}, {Name: "user-agent", Value: chromeUA}, {Name: "sec-ch-ua", Value: chromeHints},
			{Name: "sec-ch-ua-mobile", Value: "?0"}, {Name: "accept", Value: "*/*"},
			{Name: "sec-fetch-site", Value: "same-origin"}, {Name: "sec-fetch-mode", Value: "no-cors"}, {Name: "sec-fetch-dest", Value: "script"},
			{Name: "accept-encoding", Value: chromeEncAll}, {Name: "accept-language", Value: chromeLang},
		}},
		{"fetch POST", "POST", context.Background(), http.Header{"Content-Type": {"application/json"}, "Referer": {chromeRequest}}, `{"a":1}`, []lab.HeaderField{
			{Name: "content-length", Value: "7"},
			{Name: "sec-ch-ua-platform", Value: `"Linux"`}, {Name: "user-agent", Value: chromeUA}, {Name: "sec-ch-ua", Value: chromeHints},
			{Name: "content-type", Value: "application/json"}, {Name: "sec-ch-ua-mobile", Value: "?0"}, {Name: "accept", Value: "*/*"},
			{Name: "sec-fetch-site", Value: "same-origin"}, {Name: "sec-fetch-mode", Value: "cors"}, {Name: "sec-fetch-dest", Value: "empty"},
			{Name: "referer", Value: chromeRequest}, {Name: "accept-encoding", Value: chromeEncAll}, {Name: "accept-language", Value: chromeLang},
			{Name: "priority", Value: "u=1, i"},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
			req, _ := http.NewRequestWithContext(tt.ctx, tt.method, chromeRequest, strings.NewReader(tt.body))
			if tt.body == "" {
				req.Body, req.ContentLength = nil, 0
			}
			for k, v := range tt.header {
				req.Header[k] = v
			}
			if err := sendWith(t, srv, req); err != nil {
				t.Fatal(err)
			}
			got := h2Fields(t, srv.NextConn(t))
			pseudo := []string{got[0].Name, got[1].Name, got[2].Name, got[3].Name}
			if !slices.Equal(pseudo, []string{":method", ":authority", ":scheme", ":path"}) || !slices.Equal(got[4:], tt.want) {
				t.Fatalf("fields\n%v, want pseudo-headers and\n%v", got, tt.want)
			}
		})
	}
}

// Over HTTP/1.1 Host and Connection come first, the client hints are in
// lowercase and Priority is left out (A10 section 5).
func TestProfileHeadersH1(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	req, _ := http.NewRequest("GET", chromeRequest, nil)
	if err := sendWith(t, srv, req); err != nil {
		t.Fatal(err)
	}
	want := "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Connection: keep-alive\r\n" +
		"sec-ch-ua: " + chromeHints + "\r\n" +
		"sec-ch-ua-mobile: ?0\r\n" +
		"sec-ch-ua-platform: \"Linux\"\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n" +
		"User-Agent: " + chromeUA + "\r\n" +
		"Accept: " + chromeNavAcc + "\r\n" +
		"Sec-Fetch-Site: none\r\n" +
		"Sec-Fetch-Mode: navigate\r\n" +
		"Sec-Fetch-User: ?1\r\n" +
		"Sec-Fetch-Dest: document\r\n" +
		"Accept-Encoding: " + chromeEncAll + "\r\n" +
		"Accept-Language: " + chromeLang + "\r\n\r\n"
	if got := string(srv.NextConn(t).Bytes()); got != want {
		t.Fatalf("request\n%q, want\n%q", got, want)
	}
}

// Over http:// neither the client hints nor Sec-Fetch-* are sent, and
// Accept-Encoding leaves out br and zstd (A10 section 5).
func TestProfileHeadersInsecure(t *testing.T) {
	srv := lab.Start(t, lab.Options{Plain: true})
	req, _ := http.NewRequest("POST", "http://example.com/api", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "http://example.com/")
	if err := sendWith(t, srv, req); err != nil {
		t.Fatal(err)
	}
	want := "POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Connection: keep-alive\r\n" +
		"Content-Length: 7\r\n" +
		"User-Agent: " + chromeUA + "\r\n" +
		"Content-Type: application/json\r\n" +
		"Accept: */*\r\n" +
		"Referer: http://example.com/\r\n" +
		"Accept-Encoding: gzip, deflate\r\n" +
		"Accept-Language: " + chromeLang + "\r\n\r\n" +
		`{"a":1}`
	if got := string(srv.NextConn(t).Bytes()); got != want {
		t.Fatalf("request\n%q, want\n%q", got, want)
	}
}

// The request's fields take the place of the profile's, a name set to nil
// removes the profile's, and the client order comes before the profile's.
func TestProfileHeadersMerge(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	req, _ := http.NewRequest("GET", chromeRequest, nil)
	req.Header["User-Agent"] = []string{"mine"}
	req.Header["Sec-Ch-Ua"] = nil
	req.Header["Sec-Ch-Ua-Mobile"] = nil
	req.Header["Sec-Ch-Ua-Platform"] = nil
	req.Header.Set("X-First", "1")
	if err := sendWith(t, srv, req, eidolon.WithDefaultOrder(eidolon.Order{Header: []string{"x-first"}})); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range h2Fields(t, srv.NextConn(t))[4:] {
		names = append(names, f.Name)
		if f.Name == "user-agent" && f.Value != "mine" {
			t.Errorf("user-agent %q", f.Value)
		}
	}
	want := []string{"x-first", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode",
		"sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "priority"}
	if !slices.Equal(names, want) {
		t.Fatalf("names %v, want %v", names, want)
	}
}

// Exact mode sends none of the profile's headers, and ignores the
// destination.
func TestProfileHeadersExact(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	ctx := eidolon.WithExactHeaders(context.Background(), eidolon.HeaderField{Name: "x-only", Value: "1"})
	ctx = eidolon.WithFetchDest(ctx, "xhr")
	req, _ := http.NewRequestWithContext(ctx, "GET", chromeRequest, nil)
	if err := sendWith(t, srv, req); err != nil {
		t.Fatal(err)
	}
	if got := h2Fields(t, srv.NextConn(t))[4:]; !slices.Equal(got, []lab.HeaderField{{Name: "x-only", Value: "1"}}) {
		t.Fatalf("fields %v", got)
	}
}

// With the profile, a destination Sec-Fetch-Dest cannot send fails the
// request before anything is sent.
func TestProfileUnknownDest(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	req, _ := http.NewRequestWithContext(eidolon.WithFetchDest(context.Background(), "xhr"), "GET", chromeRequest, nil)
	err := sendWith(t, srv, req)
	if err == nil || !strings.Contains(err.Error(), `"xhr"`) {
		t.Fatalf("err = %v", err)
	}
	if n := srv.Accepted(); n != 0 {
		t.Fatalf("%d connections", n)
	}
}

// A profile with any of Headers, InsecureHeaders or Dests adds headers;
// with none of them, it adds none.
func TestProfileHeadersPartial(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*eidolon.Profile)
		url    string
		want   []string
	}{
		{"Dests only", func(p *eidolon.Profile) { p.Headers, p.InsecureHeaders = nil, nil }, chromeRequest,
			[]string{"Upgrade-Insecure-Requests: 1", "Sec-Fetch-Dest: document"}},
		{"InsecureHeaders only", func(p *eidolon.Profile) { p.Headers, p.Dests = nil, nil }, "http://example.com/",
			[]string{"User-Agent: " + chromeUA}},
		{"none", func(p *eidolon.Profile) { p.Headers, p.InsecureHeaders, p.Dests = nil, nil, nil }, chromeRequest, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Plain: strings.HasPrefix(tt.url, "http:")})
			p := eidolon.Chrome156Linux()
			tt.change(&p)
			profileGet(t, profileClient(t, srv, eidolon.WithProfile(p)), tt.url, nil)
			got := string(srv.NextConn(t).Bytes())
			for _, w := range tt.want {
				if !strings.Contains(got, "\r\n"+w+"\r\n") {
					t.Errorf("request %q lacks %q", got, w)
				}
			}
			if tt.want == nil && got != "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" {
				t.Errorf("request %q", got)
			}
		})
	}
}
