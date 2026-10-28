// Package browser adds the headers of a browser profile to a request: by
// context (https:// or http://) and by destination (internal/fetch), in
// the order of a navigation or of a subresource.
package browser

import (
	"net"
	"net/http"
	"net/url"
	"strings"

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
	first := req
	for first.Response != nil && first.Response.Request != nil {
		first = first.Response.Request
	}
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
	if secure {
		add = append(add,
			order.Field{Name: "Sec-Fetch-Site", Value: site(req, d.Navigation)},
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

// site returns the Sec-Fetch-Site of req by its Referer: "same-origin"
// for the origin of req, "cross-site" for another; without one, "none"
// for a navigation, as an address typed, and "same-origin" otherwise.
func site(req *http.Request, navigation bool) string {
	ref, err := url.Parse(req.Header.Get("Referer"))
	switch {
	case err != nil || ref.Host == "":
		if navigation {
			return "none"
		}
		return "same-origin"
	case origin(ref) == origin(req.URL):
		return "same-origin"
	}
	return "cross-site"
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
