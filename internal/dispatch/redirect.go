package dispatch

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// redirectHeader returns the header of a request that http.Client made
// from a redirect (req.Response set), adjusted as a browser does at each
// hop, as in httpcloak:
//
//   - Referer follows strict-origin-when-cross-origin, Chrome's default
//     policy, from the URL that answered the redirect: the URL without
//     fragment and credentials within one origin, the origin alone across
//     origins, and none from https to http. http.Client sends the whole URL
//     across origins and keeps a Referer set by the caller.
//   - Authorization and Proxy-Authorization are dropped across origins,
//     which includes https to http; http.Client keeps them within a domain
//     and its subdomains.
//
// Other requests get h as it is. h is never modified; a copy is returned
// when something changes.
func redirectHeader(req *http.Request, h http.Header) http.Header {
	if req.Response == nil || req.Response.Request == nil || req.Response.Request.URL == nil {
		return h
	}
	prev, next := req.Response.Request.URL, req.URL
	out := h.Clone()
	if out == nil {
		out = http.Header{}
	}
	cross := !sameOrigin(prev, next)
	downgrade := prev.Scheme == "https" && next.Scheme == "http"
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
	if ref := referer(prev, cross, downgrade); ref != "" {
		out.Set("Referer", ref)
	}
	return out
}

// referer returns the Referer of strict-origin-when-cross-origin for a
// request that follows prev.
func referer(prev *url.URL, cross, downgrade bool) string {
	if downgrade || (prev.Scheme != "https" && prev.Scheme != "http") {
		return ""
	}
	if cross {
		return prev.Scheme + "://" + originHost(prev) + "/"
	}
	u := *prev
	u.User = nil
	u.Fragment, u.RawFragment = "", ""
	u.Host = originHost(prev)
	return u.String()
}

// sameOrigin reports whether a and b have the same scheme, host and port,
// with the default port filled in.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		port(a) == port(b)
}

// originHost returns the host of u in lowercase, with its port unless it is
// the default one of the scheme.
func originHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
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
