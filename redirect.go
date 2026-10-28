package eidolon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxRedirects is the redirect limit of the Fetch standard, as Chrome.
const maxRedirects = 20

// do sends req and follows its redirects as the Fetch standard does
// ("HTTP-redirect fetch"). http.Client sends each hop, with the jar and the
// credentials of the URL, and stops at the first response. The Referer and
// the credentials of each hop are set by the transport, which also serves
// an http.Client built on Transport().
//
// http.Client adds the cookies of the jar to the header of the request it
// sends. Each hop gets a copy of the header, so the next hop starts from
// the fields of the caller and the jar adds its cookies again as they are
// then; the caller's request is not modified.
func (c *client) do(req *http.Request) (*http.Response, error) {
	for n := 0; ; n++ {
		sent := *req
		sent.Header = req.Header.Clone()
		resp, err := c.hc.Do(&sent)
		if err != nil {
			return nil, err
		}
		next, err := redirect(req, resp)
		if next != nil && c.hc.Jar != nil {
			dropSetCookies(next.Header, resp.Cookies())
		}
		if next == nil && err == nil {
			return resp, nil
		}
		if err == nil && n == maxRedirects {
			err = ErrTooManyRedirects
		}
		drain(resp)
		if err != nil {
			return nil, &url.Error{Op: urlErrorOp(req.Method), URL: req.URL.String(), Err: err}
		}
		req = next
	}
}

// redirect returns the request that follows resp, or nil when resp is the
// answer: not a redirect, no Location, or a body that cannot be sent
// again (no GetBody), which http.Client also returns.
//
// The method and body follow Fetch: 301 and 302 turn a POST into a GET,
// 303 turns anything but GET and HEAD into a GET, and every other case
// keeps the method and sends the body again. http.Client also turns PUT,
// DELETE and PATCH into a GET at 301 and 302. The header of the request
// is kept, without the body headers when the body is dropped and without
// the credentials once the origin changes; Fetch does not put them back.
func redirect(req *http.Request, resp *http.Response) (*http.Request, error) {
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return nil, nil
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, nil
	}
	u, err := req.URL.Parse(loc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Location header %q: %w", loc, err)
	}
	method, body := req.Method, true
	if (resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound) && req.Method == http.MethodPost ||
		resp.StatusCode == http.StatusSeeOther && req.Method != http.MethodGet && req.Method != http.MethodHead {
		method, body = http.MethodGet, false
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	if body && hasBody && req.GetBody == nil {
		return nil, nil
	}
	host := ""
	if req.Host != "" && req.Host != req.URL.Host {
		// A Host set by the caller is kept at a relative Location, as
		// http.Client.
		if l, _ := url.Parse(loc); l != nil && !l.IsAbs() {
			host = req.Host
		}
	}
	next := (&http.Request{
		Method:     method,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     req.Header.Clone(),
		Host:       host,
		Response:   resp,
	}).WithContext(req.Context())
	if next.Header == nil {
		next.Header = http.Header{}
	}
	if body && hasBody {
		if next.Body, err = req.GetBody(); err != nil {
			return nil, err
		}
		next.GetBody = req.GetBody
		next.ContentLength = req.ContentLength
	}
	cross := !sameOrigin(req.URL, u)
	for k := range next.Header {
		switch strings.ToLower(k) {
		case "authorization", "proxy-authorization", "www-authenticate", "cookie", "cookie2":
			if cross {
				delete(next.Header, k)
			}
		case "content-encoding", "content-language", "content-location", "content-type", "content-length":
			if !body {
				delete(next.Header, k)
			}
		}
	}
	return next, nil
}

// dropSetCookies removes from the Cookie fields of h the cookies of the
// caller named in set, as http.Client does when it follows redirects with
// a jar: the jar now holds them, as set, and adds them itself. The other
// cookies keep their order.
func dropSetCookies(h http.Header, set []*http.Cookie) {
	if len(set) == 0 {
		return
	}
	names := make(map[string]bool, len(set))
	for _, ck := range set {
		names[ck.Name] = true
	}
	for k, vv := range h {
		if !strings.EqualFold(k, "cookie") {
			continue
		}
		var keep []string
		for _, v := range vv {
			var pairs []string
			for _, p := range strings.Split(v, ";") {
				p = strings.TrimSpace(p)
				name, _, _ := strings.Cut(p, "=")
				if p != "" && !names[strings.TrimSpace(name)] {
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
}

// drain reads a little of a body that is not returned, so the connection
// can carry the next hop, and closes it, as http.Client.
func drain(resp *http.Response) {
	const maxBodySlurpSize = 2 << 10
	if resp.ContentLength == -1 || resp.ContentLength <= maxBodySlurpSize {
		io.CopyN(io.Discard, resp.Body, maxBodySlurpSize)
	}
	resp.Body.Close()
}

// sameOrigin reports whether a and b have the same scheme, host and port,
// with the default port filled in.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		port(a) == port(b)
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// urlErrorOp returns the url.Error Op for a method, as http.Client: "Get"
// for GET.
func urlErrorOp(method string) string {
	if method == "" {
		return "Get"
	}
	return method[:1] + strings.ToLower(method[1:])
}

// withTimeout limits do, including reading the body, to d, as
// http.Client.Timeout. Closing the body ends the deadline.
func (c *client) withTimeout(req *http.Request, d time.Duration) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), d)
	resp, err := c.do(req.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelBody ends the deadline of a request at Close.
type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
