// Package browser adds the headers of a browser profile to a request: by
// context (https:// or http://) and by destination (internal/fetch), in
// the order of a navigation or of a subresource.
package browser

import (
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/acomerlatto/eidolon-tls/internal/fetch"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// Headers are the headers a profile adds to its requests.
type Headers struct {
	// Secure is added to every https:// request, Insecure to every
	// http:// one.
	Secure, Insecure []order.Field
	// Dests holds the headers of each destination; the others get
	// Base.
	Dests map[string]Dest
	// NavigationOrder orders the headers of a navigation,
	// SubresourceOrder those of the other requests. Over HTTP/1.1, Host
	// and Connection go where they list them.
	NavigationOrder, SubresourceOrder []string
	// H1Connection is the Connection value of HTTP/1.1 requests; ""
	// sends none.
	H1Connection string
}

// Dest holds the headers of one destination.
type Dest struct {
	// Mode is sent in Sec-Fetch-Mode, over https:// only.
	Mode string
	// Accept and Priority are sent as given; "" sends none. Priority is
	// never sent over HTTP/1.1, as in Chrome.
	Accept, Priority string
	// User sends Sec-Fetch-User: ?1, over https:// only.
	User bool
	// UpgradeInsecure sends Upgrade-Insecure-Requests: 1.
	UpgradeInsecure bool
	// Navigation orders the headers by NavigationOrder.
	Navigation bool
}

// Base returns the headers of a destination the profile does not hold:
// Accept */*, no Priority, and the mode the Fetch standard gives it; a
// navigation (iframe, frame) takes those of "document" in h, without
// Sec-Fetch-User.
func (h *Headers) Base(dest string) Dest {
	switch dest {
	case "iframe", "frame", "fencedframe":
		d, ok := h.Dests["document"]
		if !ok {
			d = Dest{Accept: "*/*", UpgradeInsecure: true}
		}
		d.Mode, d.User, d.Navigation = "navigate", false, true
		return d
	case "empty", "font", "json", "manifest", "webidentity":
		return Dest{Mode: "cors", Accept: "*/*"}
	case "worker", "sharedworker", "serviceworker":
		return Dest{Mode: "same-origin", Accept: "*/*"}
	case "websocket":
		return Dest{Mode: "websocket", Accept: "*/*"}
	}
	return Dest{Mode: "no-cors", Accept: "*/*"}
}

// Request is a request with the headers of a profile.
type Request struct {
	// Header is sent over HTTP/2, H1Header over HTTP/1.1.
	Header, H1Header http.Header
	// Order is the order of the profile for the request.
	Order *order.Order
}

// Apply returns the header of req with h added: the caller's fields take
// the place of the profile's of the same name, and a name the caller set
// to no value removes the profile's. The destination is that of the first
// request of a redirect chain, as Chrome keeps it across redirects. req
// is not modified.
func (h *Headers) Apply(req *http.Request) (*Request, error) {
	urls := []*url.URL{req.URL}
	first := req
	for first.Response != nil && first.Response.Request != nil {
		first = first.Response.Request
		urls = append(urls, first.URL)
	}
	slices.Reverse(urls)
	dest, err := fetch.Dest(first)
	if err != nil {
		return nil, err
	}
	d, ok := h.Dests[dest]
	if !ok {
		d = h.Base(dest)
	}
	secure := strings.EqualFold(req.URL.Scheme, "https")

	var add []order.Field
	if secure {
		add = append(add, h.Secure...)
	} else {
		add = append(add, h.Insecure...)
	}
	if d.UpgradeInsecure {
		add = append(add, order.Field{Name: "Upgrade-Insecure-Requests", Value: "1"})
	}
	if d.Accept != "" {
		add = append(add, order.Field{Name: "Accept", Value: d.Accept})
	}
	init := initiator(first, d.Navigation)
	if o, ok := originHeader(req.Method, d.Mode, urls, init); ok {
		add = append(add, order.Field{Name: "Origin", Value: o})
	}
	if secure {
		add = append(add,
			order.Field{Name: "Sec-Fetch-Site", Value: fetchSite(urls, init)},
			order.Field{Name: "Sec-Fetch-Mode", Value: d.Mode},
			order.Field{Name: "Sec-Fetch-Dest", Value: dest})
		if d.User {
			add = append(add, order.Field{Name: "Sec-Fetch-User", Value: "?1"})
		}
	}
	if d.Priority != "" {
		add = append(add, order.Field{Name: "Priority", Value: d.Priority})
	}

	callers := make(map[string]bool, len(req.Header))
	for k := range req.Header {
		callers[strings.ToLower(k)] = true
	}
	out := req.Header.Clone()
	if out == nil {
		out = http.Header{}
	}
	for _, f := range add {
		if !callers[strings.ToLower(f.Name)] {
			out.Add(f.Name, f.Value)
		}
	}
	h1 := out.Clone()
	if !callers["priority"] {
		delete(h1, "Priority")
	}
	if h.H1Connection != "" && !callers["connection"] {
		h1.Set("Connection", h.H1Connection)
	}
	o := &order.Order{Header: h.SubresourceOrder}
	if d.Navigation {
		o.Header = h.NavigationOrder
	}
	return &Request{Header: out, H1Header: h1, Order: o}, nil
}

// initiator returns the origin that started the redirect chain whose
// first request is first: that of its Referer. Without one, a navigation
// has none, as an address typed, and another request takes the origin of
// its own URL, as a page fetching from itself.
func initiator(first *http.Request, navigation bool) *url.URL {
	if ref, err := url.Parse(first.Header.Get("Referer")); err == nil && ref.Host != "" {
		return ref
	}
	if navigation {
		return nil
	}
	return first.URL
}

// fetchSite returns the Sec-Fetch-Site of a request from init through
// urls, its redirect chain: "none" without an initiator, otherwise the
// furthest of the URLs from init, "same-origin", "same-site" or
// "cross-site" (Fetch Metadata, section 2.1).
func fetchSite(urls []*url.URL, init *url.URL) string {
	if init == nil {
		return "none"
	}
	out := "same-origin"
	for _, u := range urls {
		switch {
		case origin(u) == origin(init):
		case sameSite(u, init):
			out = "same-site"
		default:
			return "cross-site"
		}
	}
	return out
}

// sameSite reports whether a and b are of one site: the same scheme and
// registrable domain, by the public suffix list, or the same IP address.
func sameSite(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && site(a) == site(b)
}

// site returns the registrable domain of u, or its host when there is
// none, as for an IP address or localhost.
func site(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// originHeader returns the Origin of a request with method and mode from
// init through urls, and whether it sends one (Fetch, "append a request
// Origin header"): a method other than GET and HEAD sends it, and so does
// cors mode to another origin. It is "null" after a redirect across
// origins the initiator is not one of, and for a method other than GET and
// HEAD outside cors mode from https:// to http://. Without an initiator,
// none is sent.
func originHeader(method, mode string, urls []*url.URL, init *url.URL) (string, bool) {
	if init == nil {
		return "", false
	}
	cur := urls[len(urls)-1]
	unsafe := method != "" && method != http.MethodGet && method != http.MethodHead
	if !unsafe && (mode != "cors" || origin(cur) == origin(init)) {
		return "", false
	}
	for i := 1; i < len(urls); i++ {
		if origin(urls[i-1]) != origin(urls[i]) && origin(init) != origin(urls[i-1]) {
			return "null", true
		}
	}
	if mode != "cors" && strings.EqualFold(init.Scheme, "https") && strings.EqualFold(cur.Scheme, "http") {
		return "null", true
	}
	return serialize(init), true
}

// serialize returns the origin of u as Origin sends it: scheme and host,
// with the port only if it is not the default one.
func serialize(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if p := u.Port(); p != "" && p != map[string]string{"http": "80", "https": "443"}[scheme] {
		host = net.JoinHostPort(host, p)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host
}

// origin returns the origin of u: scheme, host and port, the default
// port of the scheme included.
func origin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[scheme]
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}
