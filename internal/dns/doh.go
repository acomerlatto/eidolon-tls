package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// maxDoHResponse bounds a DoH response, as Chrome
// (kDnsOverHttpResponseMaximumSize, RFC 8484 Section 6).
const maxDoHResponse = 65535

// dohType is the media type of DoH (RFC 8484, Section 6).
const dohType = "application/dns-message"

// DoH is an Exchanger over DNS over HTTPS (RFC 8484), as Chrome's
// DnsHTTPAttempt: the padded query of ID 0 in the dns parameter of a GET
// when the template has one, in the body of a POST otherwise, with
// Chrome's minimal headers. Redirects are not followed: Chrome follows
// those to https://.
type DoH struct {
	// URL is the server: a template from ParseTemplate.
	URL *Template
	// Transport sends the requests.
	Transport http.RoundTripper
}

// Template is a DoH URI template (RFC 8484, Section 3).
type Template struct {
	// Host is the host of the server, for its connections.
	Host string
	// before and after surround the dns variable; post is set when the
	// template has none.
	before, after string
	op            byte // '?', '&' or 0 for {dns}
	post          bool
}

// ParseTemplate parses a DoH URI template as Chrome checks one
// (DnsOverHttpsServerConfig): an https:// URL with at most one variable,
// dns, as {dns}, {?dns} or {&dns} (RFC 6570). Without the variable the
// queries go by POST to the URL.
func ParseTemplate(s string) (*Template, error) {
	t := &Template{}
	open := strings.IndexByte(s, '{')
	if open < 0 {
		t.before, t.post = s, true
	} else {
		end := strings.IndexByte(s[open:], '}')
		if end < 0 {
			return nil, fmt.Errorf("DoH template %q: unclosed expression", s)
		}
		switch expr := s[open+1 : open+end]; expr {
		case "dns":
		case "?dns", "&dns":
			t.op = expr[0]
		default:
			return nil, fmt.Errorf("DoH template %q: the only variable is dns, as {dns}, {?dns} or {&dns}", s)
		}
		t.before, t.after = s[:open], s[open+end+1:]
		if strings.ContainsAny(t.after, "{}") || strings.ContainsAny(t.before, "}") {
			return nil, fmt.Errorf("DoH template %q: more than one expression", s)
		}
	}
	u, err := url.Parse(t.expand("x"))
	if err != nil {
		return nil, fmt.Errorf("DoH template %q: %w", s, err)
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("DoH template %q: want an https:// URL without credentials or fragment", s)
	}
	t.Host = u.Hostname()
	return t, nil
}

// expand returns the URL with dns set to v, or without the variable for
// "".
func (t *Template) expand(v string) string {
	switch {
	case v == "":
		return t.before + t.after
	case t.op == 0:
		return t.before + v + t.after
	default:
		return t.before + string(t.op) + "dns=" + v + t.after
	}
}

// dohOrder is the order of the fields of a DoH request in Chrome: Host
// and Connection (HTTP/1.1) and Content-Length from HttpNetworkTransaction,
// before the fields of DnsHTTPAttempt, Content-Type after them, and
// Priority (HTTP/2) last, from the HTTP/2 stream.
var dohOrder = []string{"host", "connection", "content-length", "accept", "accept-language", "user-agent", "accept-encoding", "content-type", "priority"}

// Exchange sends a query for qtype of name to the server.
func (d *DoH) Exchange(ctx context.Context, name string, qtype dnsmessage.Type) ([]byte, []byte, error) {
	q, err := Query(0, name, qtype, true)
	if err != nil {
		return nil, nil, err
	}
	// The URLs parse: ParseTemplate parsed one with the variable set, and
	// base64url has only unreserved characters.
	var req *http.Request
	if d.URL.post {
		req, _ = http.NewRequestWithContext(ctx, http.MethodPost, d.URL.expand(""), bytes.NewReader(q))
	} else {
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, d.URL.expand(base64.RawURLEncoding.EncodeToString(q)), nil)
	}
	req.Header = http.Header{
		"Accept":          {dohType},
		"Accept-Language": {"*"},
		"User-Agent":      {"Chrome"},
		"Accept-Encoding": {"identity"},
		order.HeaderKey:   dohOrder,
	}
	if d.URL.post {
		req.Header.Set("Content-Type", dohType)
	}
	resp, err := d.Transport.RoundTrip(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch {
	case resp.StatusCode != http.StatusOK:
		return nil, nil, fmt.Errorf("DoH: status %d", resp.StatusCode)
	case media != dohType:
		return nil, nil, fmt.Errorf("DoH: Content-Type %q", resp.Header.Get("Content-Type"))
	case resp.ContentLength > maxDoHResponse:
		return nil, nil, errors.New("DoH: response of " + strconv.FormatInt(resp.ContentLength, 10) + " bytes")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHResponse+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > maxDoHResponse {
		return nil, nil, errors.New("DoH: response over 65535 bytes")
	}
	return q, body, nil
}
