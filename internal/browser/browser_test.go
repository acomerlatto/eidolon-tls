package browser

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/fetch"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

var testHeaders = &Headers{
	Secure:   []order.Field{{Name: "user-agent", Value: "UA"}, {Name: "sec-ch-ua", Value: "hints"}},
	Insecure: []order.Field{{Name: "user-agent", Value: "UA"}},
	Dests: map[string]Dest{
		"document": {Mode: "navigate", Accept: "text/html", Priority: "u=0, i", User: true, UpgradeInsecure: true, Navigation: true},
		"empty":    {Mode: "cors", Accept: "*/*", Priority: "u=1, i"},
		"script":   {Mode: "no-cors", Accept: "*/*"},
		"image":    {Mode: "no-cors"},
	},
	NavigationOrder:  []string{"host", "connection", "sec-ch-ua", "user-agent"},
	SubresourceOrder: []string{"host", "connection", "user-agent", "sec-ch-ua"},
	H1Connection:     "keep-alive",
}

func newReq(t *testing.T, method, url string, header http.Header) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if header != nil {
		req.Header = header
	}
	return req
}

func TestApply(t *testing.T) {
	for _, tt := range []struct {
		name   string
		req    *http.Request
		header http.Header
		order  []string
	}{
		{"navigation", newReq(t, "GET", "https://a.test/", nil), http.Header{
			"User-Agent": {"UA"}, "Sec-Ch-Ua": {"hints"}, "Upgrade-Insecure-Requests": {"1"}, "Accept": {"text/html"},
			"Sec-Fetch-Site": {"none"}, "Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-User": {"?1"}, "Sec-Fetch-Dest": {"document"},
			"Priority": {"u=0, i"},
		}, testHeaders.NavigationOrder},
		{"fetch", newReq(t, "POST", "https://a.test/api", http.Header{"Content-Type": {"application/json"}}), http.Header{
			"Content-Type": {"application/json"}, "User-Agent": {"UA"}, "Sec-Ch-Ua": {"hints"}, "Accept": {"*/*"}, "Origin": {"https://a.test"},
			"Sec-Fetch-Site": {"same-origin"}, "Sec-Fetch-Mode": {"cors"}, "Sec-Fetch-Dest": {"empty"},
			"Priority": {"u=1, i"},
		}, testHeaders.SubresourceOrder},
		{"script without priority", newReq(t, "GET", "https://a.test/app.js", http.Header{"Sec-Fetch-Dest": {"script"}}), http.Header{
			"User-Agent": {"UA"}, "Sec-Ch-Ua": {"hints"}, "Accept": {"*/*"},
			"Sec-Fetch-Site": {"same-origin"}, "Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"script"},
		}, testHeaders.SubresourceOrder},
		{"no accept", newReq(t, "GET", "https://a.test/i.png", http.Header{"Sec-Fetch-Dest": {"image"}}), http.Header{
			"User-Agent": {"UA"}, "Sec-Ch-Ua": {"hints"},
			"Sec-Fetch-Site": {"same-origin"}, "Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"image"},
		}, testHeaders.SubresourceOrder},
		{"insecure navigation", newReq(t, "GET", "http://a.test/", nil), http.Header{
			"User-Agent": {"UA"}, "Upgrade-Insecure-Requests": {"1"}, "Accept": {"text/html"}, "Priority": {"u=0, i"},
		}, testHeaders.NavigationOrder},
		{"insecure fetch", newReq(t, "DELETE", "HTTP://a.test/x", nil), http.Header{
			"User-Agent": {"UA"}, "Accept": {"*/*"}, "Priority": {"u=1, i"}, "Origin": {"http://a.test"},
		}, testHeaders.SubresourceOrder},
		{"caller values and removals", newReq(t, "GET", "https://a.test/", http.Header{
			"user-agent": {"mine"}, "Sec-Ch-Ua": nil, "Accept": {"application/json"}, "Sec-Fetch-Site": {"cross-site"}, "X-A": {"1"},
		}), http.Header{
			"user-agent": {"mine"}, "Sec-Ch-Ua": nil, "Accept": {"application/json"}, "Sec-Fetch-Site": {"cross-site"}, "X-A": {"1"},
			"Sec-Fetch-Mode": {"cors"}, "Sec-Fetch-Dest": {"empty"}, "Priority": {"u=1, i"},
		}, testHeaders.SubresourceOrder},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := tt.req.Header.Clone()
			got, err := testHeaders.Apply(tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Header, tt.header) {
				t.Errorf("header\n%v, want\n%v", got.Header, tt.header)
			}
			if !slices.Equal(got.Order.Header, tt.order) || got.Order.Pseudo != nil {
				t.Errorf("order %v, want %v", got.Order, tt.order)
			}
			if !reflect.DeepEqual(tt.req.Header, before) {
				t.Errorf("request header changed to %v", tt.req.Header)
			}
		})
	}
}

// Over HTTP/1.1 the profile's Priority is left out and Connection added;
// the caller's of either is kept.
func TestApplyH1(t *testing.T) {
	got, err := testHeaders.Apply(newReq(t, "GET", "https://a.test/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.H1Header["Priority"]; ok || got.H1Header.Get("Connection") != "keep-alive" {
		t.Errorf("H1 header %v", got.H1Header)
	}
	if got.Header.Get("Priority") == "" || got.Header.Get("Connection") != "" {
		t.Errorf("H2 header %v", got.Header)
	}
	got, err = testHeaders.Apply(newReq(t, "GET", "https://a.test/", http.Header{"Priority": {"u=4"}}))
	if err != nil {
		t.Fatal(err)
	}
	if v := got.H1Header["Priority"]; !slices.Equal(v, []string{"u=4"}) {
		t.Errorf("caller's Priority over HTTP/1.1: %v", got.H1Header)
	}
	got, err = testHeaders.Apply(newReq(t, "GET", "https://a.test/", http.Header{"priority": {"u=4"}, "connection": {"close"}}))
	if err != nil {
		t.Fatal(err)
	}
	if want := (http.Header{"priority": {"u=4"}, "connection": {"close"}}); got.H1Header.Get("Connection") != "" || len(got.H1Header["Priority"]) != 0 ||
		!slices.Equal(got.H1Header["priority"], want["priority"]) || !slices.Equal(got.H1Header["connection"], want["connection"]) {
		t.Errorf("H1 header %v", got.H1Header)
	}
	h := *testHeaders
	h.H1Connection = ""
	got, _ = h.Apply(newReq(t, "GET", "https://a.test/", nil))
	if _, ok := got.H1Header["Connection"]; ok {
		t.Errorf("Connection without H1Connection: %v", got.H1Header)
	}
}

// A redirect keeps the destination of the first request: a fetch POST
// redirected to a GET stays a fetch.
func TestApplyRedirect(t *testing.T) {
	first := newReq(t, "POST", "https://a.test/api", http.Header{"Content-Type": {"application/json"}})
	mid := newReq(t, "GET", "https://a.test/moved", nil)
	mid.Response = &http.Response{Request: first}
	last := newReq(t, "GET", "https://a.test/there", nil)
	last.Response = &http.Response{Request: mid}
	got, err := testHeaders.Apply(last)
	if err != nil {
		t.Fatal(err)
	}
	if d, m := got.Header.Get("Sec-Fetch-Dest"), got.Header.Get("Sec-Fetch-Mode"); d != "empty" || m != "cors" {
		t.Fatalf("dest %q, mode %q", d, m)
	}

	// The initiator is the Referer of the first request, and the whole
	// chain counts: a navigation from a.test through b.test back to
	// a.test is cross-site; a POST redirected across origins sends Origin
	// null; the caller's Origin and Sec-Fetch-Site stay.
	first = newReq(t, "POST", "https://b.test/form", http.Header{
		"Referer": {"https://a.test/page"}, "Content-Type": {"application/x-www-form-urlencoded"},
	})
	mid = newReq(t, "POST", "https://c.test/next", http.Header{"Referer": {"https://a.test/"}})
	mid.Response = &http.Response{Request: first}
	last = newReq(t, "POST", "https://a.test/done", http.Header{"Referer": {"https://a.test/"}})
	last.Response = &http.Response{Request: mid}
	got, err = testHeaders.Apply(last)
	if err != nil {
		t.Fatal(err)
	}
	if s, o, d := got.Header.Get("Sec-Fetch-Site"), got.Header.Get("Origin"), got.Header.Get("Sec-Fetch-Dest"); s != "cross-site" || o != "null" || d != "document" {
		t.Fatalf("site %q, origin %q, dest %q", s, o, d)
	}
	last.Header.Set("Origin", "https://mine.test")
	last.Header.Set("Sec-Fetch-Site", "same-origin")
	got, _ = testHeaders.Apply(last)
	if s, o := got.Header.Get("Sec-Fetch-Site"), got.Header.Get("Origin"); s != "same-origin" || o != "https://mine.test" {
		t.Fatalf("caller's: site %q, origin %q", s, o)
	}
	// A navigation with no initiator stays "none" through its redirects.
	first = newReq(t, "GET", "https://a.test/", nil)
	last = newReq(t, "GET", "https://b.test/", nil)
	last.Response = &http.Response{Request: first}
	got, _ = testHeaders.Apply(last)
	if s := got.Header.Get("Sec-Fetch-Site"); s != "none" {
		t.Fatalf("typed navigation redirected: site %q", s)
	}
}

func TestApplyUnknownDest(t *testing.T) {
	req := newReq(t, "GET", "https://a.test/", nil)
	req = req.WithContext(fetch.WithDest(context.Background(), "xhr"))
	if _, err := testHeaders.Apply(req); err == nil {
		t.Fatal("no error")
	}
}

func TestBase(t *testing.T) {
	for dest, want := range map[string]Dest{
		"iframe":    {Mode: "navigate", Accept: "text/html", Priority: "u=0, i", UpgradeInsecure: true, Navigation: true},
		"frame":     {Mode: "navigate", Accept: "text/html", Priority: "u=0, i", UpgradeInsecure: true, Navigation: true},
		"font":      {Mode: "cors", Accept: "*/*"},
		"manifest":  {Mode: "cors", Accept: "*/*"},
		"worker":    {Mode: "same-origin", Accept: "*/*"},
		"websocket": {Mode: "websocket", Accept: "*/*"},
		"video":     {Mode: "no-cors", Accept: "*/*"},
		"style":     {Mode: "no-cors", Accept: "*/*"},
	} {
		if got := testHeaders.Base(dest); got != want {
			t.Errorf("Base(%q) = %+v, want %+v", dest, got, want)
		}
	}
	if got := (&Headers{}).Base("iframe"); got != (Dest{Mode: "navigate", Accept: "*/*", UpgradeInsecure: true, Navigation: true}) {
		t.Errorf("Base(iframe) without document = %+v", got)
	}
	// A destination the profile lacks gets Base in Apply.
	got, err := testHeaders.Apply(newReq(t, "GET", "https://a.test/f.woff2", http.Header{"Sec-Fetch-Dest": {"font"}}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.Get("Sec-Fetch-Mode") != "cors" || got.Header.Get("Accept") != "*/*" || got.Header.Get("Priority") != "" {
		t.Errorf("font: %v", got.Header)
	}
}

func mustURLs(t *testing.T, raw ...string) []*url.URL {
	t.Helper()
	var out []*url.URL
	for _, r := range raw {
		u, err := url.Parse(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, u)
	}
	return out
}

func TestFetchSite(t *testing.T) {
	for _, tt := range []struct {
		init string // "" for none
		urls []string
		want string
	}{
		{"", []string{"https://a.test/"}, "none"},
		{"", []string{"https://a.test/", "https://b.test/"}, "none"},
		{"https://a.test/page", []string{"https://A.test:443/x"}, "same-origin"},
		{"https://a.test/page", []string{"https://www.a.test/x"}, "same-site"},
		{"https://h1.lab.test/", []string{"https://lab.test/x"}, "same-site"},
		{"https://a.test/page", []string{"https://a.test:8443/x"}, "same-site"},
		{"https://a.test:00443/page", []string{"https://a.test/x"}, "same-origin"},
		{"http://a.test/page", []string{"https://a.test/x"}, "cross-site"},
		{"https://a.test/page", []string{"https://b.test/x"}, "cross-site"},
		{"https://a.github.io/", []string{"https://b.github.io/x"}, "cross-site"},
		{"https://x.a.co.uk/", []string{"https://y.a.co.uk/x"}, "same-site"},
		{"https://b.co.uk/", []string{"https://a.co.uk/x"}, "cross-site"},
		{"https://127.0.0.1/", []string{"https://127.0.0.1:8443/x"}, "same-site"},
		{"https://127.0.0.1/", []string{"https://127.0.0.2/x"}, "cross-site"},
		{"https://10.0.0.1/", []string{"https://10.1.0.1/x"}, "cross-site"},
		{"https://localhost/", []string{"https://localhost:8443/x"}, "same-site"},
		// Hosts compare as the URL standard serializes them.
		{"https://bücher.example/", []string{"https://xn--bcher-kva.example/x"}, "same-origin"},
		{"https://a.bücher.example/", []string{"https://b.xn--bcher-kva.example/x"}, "same-site"},
		{"https://[0:0::1]/", []string{"https://[::1]/x"}, "same-origin"},
		{"https://0x7f.1/", []string{"https://127.0.0.1/x"}, "same-origin"},
		// The furthest URL of the chain counts.
		{"https://a.test/", []string{"https://a.test/1", "https://www.a.test/2", "https://a.test/3"}, "same-site"},
		{"https://a.test/", []string{"https://a.test/1", "https://b.test/2", "https://a.test/3"}, "cross-site"},
		{"https://a.test/", []string{"https://www.a.test/1", "https://a.test/2"}, "same-site"},
		{"https://a.test/", []string{"https://www.a.test/1", "https://b.test/2"}, "cross-site"},
	} {
		var init *url.URL
		if tt.init != "" {
			init = mustURLs(t, tt.init)[0]
		}
		if got := fetchSite(mustURLs(t, tt.urls...), init); got != tt.want {
			t.Errorf("fetchSite(%v from %q) = %q, want %q", tt.urls, tt.init, got, tt.want)
		}
	}
	// A URL built by hand may spell its scheme in uppercase.
	u := &url.URL{Scheme: "HTTPS", Host: "a.test", Path: "/"}
	if got := fetchSite([]*url.URL{u}, mustURLs(t, "https://a.test/page")[0]); got != "same-origin" {
		t.Errorf("fetchSite with scheme HTTPS = %q", got)
	}
}

func TestInitiator(t *testing.T) {
	req := newReq(t, "GET", "https://a.test/x", http.Header{"Referer": {"https://b.test/page"}})
	if got := initiator(req, true); got == nil || got.Host != "b.test" {
		t.Errorf("with Referer: %v", got)
	}
	for _, ref := range []string{"", "/relative", "not a url\x7f"} {
		req = newReq(t, "GET", "https://a.test/x", http.Header{"Referer": {ref}})
		if got := initiator(req, true); got != nil {
			t.Errorf("navigation with Referer %q: %v", ref, got)
		}
		if got := initiator(req, false); got != req.URL {
			t.Errorf("subresource with Referer %q: %v", ref, got)
		}
	}
}

func TestOriginHeader(t *testing.T) {
	for _, tt := range []struct {
		name         string
		method, mode string
		init         string
		urls         []string
		want         string // "" for none
	}{
		{"GET same origin", "GET", "cors", "https://a.test/", []string{"https://a.test/x"}, ""},
		{"no method", "", "navigate", "https://a.test/", []string{"https://b.test/x"}, ""},
		{"GET no-cors", "GET", "no-cors", "https://a.test/", []string{"https://b.test/x"}, ""},
		{"HEAD navigate", "HEAD", "navigate", "https://a.test/", []string{"https://b.test/x"}, ""},
		{"GET cors cross", "GET", "cors", "https://a.test/", []string{"https://b.test/x"}, "https://a.test"},
		{"GET cors other port", "GET", "cors", "https://a.test/", []string{"https://a.test:8443/x"}, "https://a.test"},
		{"POST same origin", "POST", "cors", "https://a.test/", []string{"https://a.test/x"}, "https://a.test"},
		{"POST navigate", "POST", "navigate", "https://a.test/", []string{"https://b.test/x"}, "https://a.test"},
		{"DELETE port", "DELETE", "cors", "https://a.test:8443/p", []string{"https://a.test:8443/x"}, "https://a.test:8443"},
		{"default port", "PUT", "cors", "http://A.test:80/p", []string{"http://a.test/x"}, "http://a.test"},
		{"uppercase", "PUT", "cors", "HTTPS://A.TEST:443/p", []string{"https://a.test/x"}, "https://a.test"},
		{"IPv6", "POST", "cors", "https://[::1]/p", []string{"https://[::1]/x"}, "https://[::1]"},
		{"IPv6 long", "POST", "cors", "https://[0:0::1]/p", []string{"https://[::1]/x"}, "https://[::1]"},
		{"IDN", "POST", "cors", "https://Bücher.example/p", []string{"https://xn--bcher-kva.example/x"}, "https://xn--bcher-kva.example"},
		{"port with zeros", "POST", "cors", "https://a.test:0443/p", []string{"https://a.test/x"}, "https://a.test"},
		{"other port with zeros", "POST", "cors", "https://a.test:08443/p", []string{"https://a.test:8443/x"}, "https://a.test:8443"},
		{"port with zeros same origin", "GET", "cors", "http://a.test:0080/p", []string{"http://a.test/x"}, ""},
		{"IDN same origin", "GET", "cors", "https://bücher.example/p", []string{"https://xn--bcher-kva.example/x"}, ""},
		{"no initiator", "POST", "navigate", "", []string{"https://a.test/x"}, ""},
		{"downgrade", "POST", "navigate", "https://a.test/", []string{"http://a.test/x"}, "null"},
		{"downgrade cors", "POST", "cors", "https://a.test/", []string{"http://a.test/x"}, "https://a.test"},
		{"redirect across origins", "POST", "cors", "https://a.test/", []string{"https://b.test/1", "https://c.test/2"}, "null"},
		{"redirect from initiator", "POST", "cors", "https://a.test/", []string{"https://a.test/1", "https://b.test/2"}, "https://a.test"},
		{"redirect in one origin", "POST", "cors", "https://a.test/", []string{"https://b.test/1", "https://b.test/2"}, "https://a.test"},
		{"redirect back", "GET", "cors", "https://a.test/", []string{"https://b.test/1", "https://a.test/2", "https://c.test/3"}, "null"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var init *url.URL
			if tt.init != "" {
				init = mustURLs(t, tt.init)[0]
			}
			got, ok := originHeader(tt.method, tt.mode, mustURLs(t, tt.urls...), init)
			if ok != (tt.want != "") || got != tt.want {
				t.Fatalf("originHeader = %q, %v; want %q", got, ok, tt.want)
			}
		})
	}
	// A URL built by hand may spell its scheme in uppercase.
	init := &url.URL{Scheme: "HTTPS", Host: "a.test"}
	if got, _ := originHeader("POST", "cors", mustURLs(t, "https://a.test/x"), init); got != "https://a.test" {
		t.Errorf("Origin from scheme HTTPS = %q", got)
	}
}
