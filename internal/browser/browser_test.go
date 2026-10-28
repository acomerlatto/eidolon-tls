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
			"Content-Type": {"application/json"}, "User-Agent": {"UA"}, "Sec-Ch-Ua": {"hints"}, "Accept": {"*/*"},
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
			"User-Agent": {"UA"}, "Accept": {"*/*"}, "Priority": {"u=1, i"},
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

func TestSite(t *testing.T) {
	for _, tt := range []struct {
		url, referer string
		navigation   bool
		want         string
	}{
		{"https://a.test/", "", true, "none"},
		{"https://a.test/", "", false, "same-origin"},
		{"https://a.test/", "not a url\x7f", true, "none"},
		{"https://a.test/x", "https://A.test:443/page", false, "same-origin"},
		{"https://a.test:8443/x", "https://a.test/page", false, "cross-site"},
		{"https://a.test/x", "http://a.test/page", true, "cross-site"},
		{"https://a.test/x", "https://b.test/page", false, "cross-site"},
	} {
		req := newReq(t, "GET", tt.url, http.Header{"Referer": {tt.referer}})
		if got := site(req, tt.navigation); got != tt.want {
			t.Errorf("site(%s from %q, navigation %v) = %q, want %q", tt.url, tt.referer, tt.navigation, got, tt.want)
		}
	}
	// A URL built by hand may spell its scheme in uppercase.
	req := newReq(t, "GET", "https://a.test/", http.Header{"Referer": {"https://a.test/page"}})
	req.URL = &url.URL{Scheme: "HTTPS", Host: "a.test", Path: "/"}
	if got := site(req, false); got != "same-origin" {
		t.Errorf("site with scheme HTTPS = %q", got)
	}
}
