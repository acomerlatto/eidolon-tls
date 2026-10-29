package dispatch

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/acomerlatto/eidolon-tls/internal/target"
)

// redirectHeader returns the header of a request made from a redirect
// (req.Response set), adjusted at each hop as the Fetch standard does
// ("HTTP-redirect fetch"), walking the chain of requests through
// Response.Request:
//
//   - Referer comes from the referrer of the first request, its Referer
//     header, under strict-origin-when-cross-origin, Chrome's default
//     policy, against the URL of this hop: the referrer without fragment
//     and credentials within one origin, its origin alone across origins,
//     and none from https to http. A first request without Referer sends
//     none at any hop. http.Client sends the URL that answered the
//     redirect instead.
//   - Authorization and Proxy-Authorization are dropped once any hop of
//     the chain changed origin, which includes https to http, and stay
//     dropped. http.Client compares the first request with this one
//     only, so they come back at A -> B -> A.
//
// Other requests get h as it is. h is never modified; a copy is returned
// when something changes.
func redirectHeader(req *http.Request, h http.Header) http.Header {
	if req.Response == nil || req.Response.Request == nil || req.Response.Request.URL == nil {
		return h
	}
	cross := false
	first, next := req, req.URL
	for first.Response != nil && first.Response.Request != nil && first.Response.Request.URL != nil {
		prev := first.Response.Request
		if !sameOrigin(prev.URL, next) {
			cross = true
		}
		first, next = prev, prev.URL
	}
	out := h.Clone()
	if out == nil {
		out = http.Header{}
	}
	for k := range out {
		switch strings.ToLower(k) {
		case "referer":
			delete(out, k)
		case "authorization", "proxy-authorization":
			if cross {
				delete(out, k)
			}
		}
	}
	if ref := referer(first.Header.Get("Referer"), req.URL); ref != "" {
		out.Set("Referer", ref)
	}
	return out
}

// referer returns the Referer of strict-origin-when-cross-origin for the
// referrer ref and a request to u; none when ref is not an http(s) URL.
func referer(ref string, u *url.URL) string {
	r, err := url.Parse(ref)
	if err != nil || r.Host == "" || (r.Scheme != "https" && r.Scheme != "http") {
		return ""
	}
	if r.Scheme == "https" && u.Scheme == "http" {
		return ""
	}
	if !sameOrigin(r, u) {
		return r.Scheme + "://" + originHost(r) + "/"
	}
	c := *r
	c.User = nil
	c.Fragment, c.RawFragment = "", ""
	c.Host = originHost(r)
	if c.Path == "" {
		c.Path = "/"
	}
	return c.String()
}

// sameOrigin reports whether a and b have the same scheme, host and port,
// with the default port filled in and the hosts normalized as
// target.Parse does.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		target.Host(a) == target.Host(b) &&
		port(a) == port(b)
}

// originHost returns the host of u normalized as target.Parse does, with
// its port unless it is the default one of the scheme.
func originHost(u *url.URL) string {
	host := target.Host(u)
	if p := u.Port(); p != "" && p != defaultPort(u.Scheme) {
		return net.JoinHostPort(host, p)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return defaultPort(u.Scheme)
}

func defaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}
