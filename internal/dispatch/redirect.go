package dispatch

import (
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
//   - After such a hop, Cookie2 is dropped and so are the cookies of
//     Cookie the first request sent, by name and value, as client.Do
//     drops the caller's: http.Client copies them to the same domain and
//     its subdomains whatever the scheme. With http.Client.Jar, the jar
//     adds its cookies to the first request too, so the same cookie added
//     again for this hop is dropped as well.
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
		case "authorization", "proxy-authorization", "cookie2":
			if cross {
				delete(out, k)
			}
		case "cookie":
			if cross {
				dropCookies(out, k, first.Header)
			}
		}
	}
	if ref := referer(first.Header.Get("Referer"), req.URL); ref != "" {
		out.Set("Referer", ref)
	}
	return out
}

// dropCookies removes from the field k of h the cookies, as name=value,
// of the Cookie fields of from. The others keep their order.
func dropCookies(h http.Header, k string, from http.Header) {
	sent := map[string]bool{}
	for _, v := range from.Values("Cookie") {
		for _, p := range strings.Split(v, ";") {
			sent[strings.TrimSpace(p)] = true
		}
	}
	var keep []string
	for _, v := range h[k] {
		var pairs []string
		for _, p := range strings.Split(v, ";") {
			if p = strings.TrimSpace(p); p != "" && !sent[p] {
				pairs = append(pairs, p)
			}
		}
		if len(pairs) > 0 {
			keep = append(keep, strings.Join(pairs, "; "))
		}
	}
	if len(keep) == 0 {
		delete(h, k)
	} else {
		h[k] = keep
	}
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
		return r.Scheme + "://" + target.Authority(r) + "/"
	}
	c := *r
	c.User = nil
	c.Fragment, c.RawFragment = "", ""
	c.Host = target.Authority(r)
	if c.Path == "" {
		c.Path = "/"
	}
	return c.String()
}

// sameOrigin reports whether a and b have the same scheme, host and port,
// with the default port filled in and the host and port normalized as
// target.Parse does.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		target.Host(a) == target.Host(b) &&
		target.Port(a) == target.Port(b)
}
