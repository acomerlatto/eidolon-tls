// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpcommon

import (
	"context"
	"errors"
	"fmt"
	"maps" // [eidolon]
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"slices" // [eidolon]
	"sort"
	"strconv"
	"strings"

	"github.com/acomerlatto/eidolon-tls/internal/http2/hpack"
	"github.com/acomerlatto/eidolon-tls/internal/order" // [eidolon]
	"golang.org/x/net/http/httpguts"
)

var (
	ErrRequestHeaderListSize = errors.New("request header list larger than peer's advertised limit")
)

// Request is a subset of http.Request.
// It'd be simpler to pass an *http.Request, of course, but we can't depend on net/http
// without creating a dependency cycle.
type Request struct {
	URL                 *url.URL
	Method              string
	Host                string
	Header              map[string][]string
	Trailer             map[string][]string
	ActualContentLength int64 // 0 means 0, -1 means unknown
}

// EncodeHeadersParam is parameters to EncodeHeaders.
type EncodeHeadersParam struct {
	Request Request

	// AddGzipHeader indicates that an "accept-encoding: gzip" header should be
	// added to the request.
	AddGzipHeader bool

	// PeerMaxHeaderListSize, when non-zero, is the peer's MAX_HEADER_LIST_SIZE setting.
	PeerMaxHeaderListSize uint64

	// DefaultUserAgent is the User-Agent header to send when the request
	// neither contains a User-Agent nor disables it.
	DefaultUserAgent string
}

// EncodeHeadersResult is the result of EncodeHeaders.
type EncodeHeadersResult struct {
	HasBody     bool
	HasTrailers bool
}

// EncodeHeaders constructs request headers common to HTTP/2 and HTTP/3.
// It validates a request and calls headerf with each pseudo-header and header
// for the request.
// The headerf function is called with the validated, canonicalized header name.
func EncodeHeaders(ctx context.Context, param EncodeHeadersParam, headerf func(name, value string)) (res EncodeHeadersResult, _ error) {
	req := param.Request

	// [eidolon] In exact mode the fields of the context replace req.Header,
	// which is neither checked nor sent. A Host field gives :authority.
	exact := order.ExactFromContext(ctx)
	header := req.Header
	if exact != nil {
		header = make(map[string][]string)
		for _, f := range exact {
			header[f.Name] = append(header[f.Name], f.Value)
		}
	}

	// Check for invalid connection-level headers.
	if err := checkConnHeaders(header); err != nil {
		return res, err
	}

	if req.URL == nil {
		return res, errors.New("Request.URL is nil")
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if exact != nil {
		if err := checkExact(exact, req.ActualContentLength, &host); err != nil {
			return res, err
		}
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return res, err
	}
	if !httpguts.ValidHostHeader(host) {
		return res, errors.New("invalid Host header")
	}

	// isNormalConnect is true if this is a non-extended CONNECT request.
	isNormalConnect := false
	var protocol string
	if vv := header[":protocol"]; len(vv) > 0 {
		protocol = vv[0]
	}
	if req.Method == "CONNECT" && protocol == "" {
		isNormalConnect = true
	} else if protocol != "" && req.Method != "CONNECT" {
		return res, errors.New("invalid :protocol header in non-CONNECT request")
	}

	// Validate the path, except for non-extended CONNECT requests which have no path.
	var path string
	if !isNormalConnect {
		path = req.URL.RequestURI()
		if !validPseudoPath(path) {
			orig := path
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
			if !validPseudoPath(path) {
				if req.URL.Opaque != "" {
					return res, fmt.Errorf("invalid request :path %q from URL.Opaque = %q", orig, req.URL.Opaque)
				} else {
					return res, fmt.Errorf("invalid request :path %q", orig)
				}
			}
		}
	}

	// Check for any invalid headers+trailers and return an error before we
	// potentially pollute our hpack state. (We want to be able to
	// continue to reuse the hpack encoder for future requests)
	if err := validateHeaders(header, exact == nil); err != "" {
		return res, fmt.Errorf("invalid HTTP header %s", err)
	}
	if err := validateHeaders(req.Trailer, false); err != "" {
		return res, fmt.Errorf("invalid HTTP trailer %s", err)
	}

	trailers, err := commaSeparatedTrailers(req.Trailer)
	if err != nil {
		return res, err
	}

	enumerateHeaders := func(f func(name, value string)) {
		// [eidolon] Collect the fields and emit them sorted once
		// enumeration ends. Without an order in the context, the regular
		// headers are sorted alphabetically, never in map order.
		o := order.FromContext(ctx)
		if o == nil {
			o = &order.Order{}
		}
		emit := f
		var fields []order.Field
		f = func(name, value string) {
			fields = append(fields, order.Field{Name: name, Value: value})
		}
		defer func() {
			sorted := o.Sort
			if exact != nil {
				sorted = o.SortPseudo // the exact fields keep their order
			}
			for _, hf := range sorted(fields) {
				emit(hf.Name, hf.Value)
			}
		}()

		// 8.1.2.3 Request Pseudo-Header Fields
		// The :path pseudo-header field includes the path and query parts of the
		// target URI (the path-absolute production and optionally a '?' character
		// followed by the query production, see Sections 3.3 and 3.4 of
		// [RFC3986]).
		f(":authority", host)
		m := req.Method
		if m == "" {
			m = "GET"
		}
		f(":method", m)
		if !isNormalConnect {
			f(":path", path)
			f(":scheme", req.URL.Scheme)
		}
		if protocol != "" {
			f(":protocol", protocol)
		}
		if trailers != "" {
			f("trailer", trailers)
		}

		// [eidolon] Exact mode: the fields as given, Cookie not split, and
		// nothing of the engine (content-length, accept-encoding,
		// user-agent). Host is :authority; connection-specific fields,
		// valid in HTTP/1.1, are left out as below.
		if exact != nil {
			for _, hf := range exact {
				switch {
				case asciiEqualFold(hf.Name, "host"),
					asciiEqualFold(hf.Name, "connection"),
					asciiEqualFold(hf.Name, "proxy-connection"),
					asciiEqualFold(hf.Name, "transfer-encoding"),
					asciiEqualFold(hf.Name, "upgrade"),
					asciiEqualFold(hf.Name, "keep-alive"):
					continue
				}
				f(hf.Name, hf.Value)
			}
			return
		}

		var didUA bool
		// [eidolon] Keys in byte order: two keys of one name in different
		// case ("X-A", "x-a") are merged the same way every time.
		for _, k := range slices.Sorted(maps.Keys(req.Header)) {
			vv := req.Header[k]
			if asciiEqualFold(k, "host") || asciiEqualFold(k, "content-length") {
				// Host is :authority, already sent.
				// Content-Length is automatic, set below.
				continue
			} else if asciiEqualFold(k, "connection") ||
				asciiEqualFold(k, "proxy-connection") ||
				asciiEqualFold(k, "transfer-encoding") ||
				asciiEqualFold(k, "upgrade") ||
				asciiEqualFold(k, "keep-alive") {
				// Per 8.1.2.2 Connection-Specific Header
				// Fields, don't send connection-specific
				// fields. We have already checked if any
				// are error-worthy so just ignore the rest.
				continue
			} else if asciiEqualFold(k, "user-agent") {
				// Match Go's http1 behavior: at most one
				// User-Agent. If set to nil or empty string,
				// then omit it. Otherwise if not mentioned,
				// include the default (below).
				didUA = true
				if len(vv) < 1 {
					continue
				}
				vv = vv[:1]
				if vv[0] == "" {
					continue
				}
			} else if asciiEqualFold(k, "cookie") {
				// Per 8.1.2.5 To allow for better compression efficiency, the
				// Cookie header field MAY be split into separate header fields,
				// each with one or more cookie-pairs.
				// [eidolon] Split as Chrome (cookieCrumbs).
				for _, v := range vv {
					for _, c := range cookieCrumbs(v) {
						f("cookie", c)
					}
				}
				continue
			} else if k == ":protocol" {
				// :protocol pseudo-header was already sent above.
				continue
			}

			for _, v := range vv {
				f(k, v)
			}
		}
		if shouldSendReqContentLength(req.Method, req.ActualContentLength) {
			f("content-length", strconv.FormatInt(req.ActualContentLength, 10))
		}
		if param.AddGzipHeader {
			f("accept-encoding", "gzip")
		}
		if !didUA && param.DefaultUserAgent != "" {
			f("user-agent", param.DefaultUserAgent)
		}
	}

	// Do a first pass over the headers counting bytes to ensure
	// we don't exceed cc.peerMaxHeaderListSize. This is done as a
	// separate pass before encoding the headers to prevent
	// modifying the hpack state.
	if param.PeerMaxHeaderListSize > 0 {
		hlSize := uint64(0)
		enumerateHeaders(func(name, value string) {
			hf := hpack.HeaderField{Name: name, Value: value}
			hlSize += uint64(hf.Size())
		})

		if hlSize > param.PeerMaxHeaderListSize {
			return res, ErrRequestHeaderListSize
		}
	}

	trace := httptrace.ContextClientTrace(ctx)

	// Header list size is ok. Write the headers.
	enumerateHeaders(func(name, value string) {
		name, ascii := LowerHeader(name)
		if !ascii {
			// Skip writing invalid headers. Per RFC 7540, Section 8.1.2, header
			// field names have to be ASCII characters (just as in HTTP/1.x).
			return
		}

		headerf(name, value)

		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField(name, []string{value})
		}
	})

	res.HasBody = req.ActualContentLength != 0
	res.HasTrailers = trailers != ""
	return res, nil
}

// IsRequestGzip reports whether we should add an Accept-Encoding: gzip header
// for a request.
func IsRequestGzip(method string, header map[string][]string, disableCompression bool) bool {
	// TODO(bradfitz): this is a copy of the logic in net/http. Unify somewhere?
	if !disableCompression &&
		len(header["Accept-Encoding"]) == 0 &&
		len(header["Range"]) == 0 &&
		method != "HEAD" {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as universally supported anyway.
		// See: https://zlib.net/zlib_faq.html#faq39
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   http://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		return true
	}
	return false
}

// checkConnHeaders checks whether req has any invalid connection-level headers.
//
// https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2-3
// https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2-1
//
// Certain headers are special-cased as okay but not transmitted later.
// For example, we allow "Transfer-Encoding: chunked", but drop the header when encoding.
func checkConnHeaders(h map[string][]string) error {
	if vv := h["Upgrade"]; len(vv) > 0 && (vv[0] != "" && vv[0] != "chunked") {
		return fmt.Errorf("invalid Upgrade request header: %q", vv)
	}
	if vv := h["Transfer-Encoding"]; len(vv) > 0 && (len(vv) > 1 || vv[0] != "" && vv[0] != "chunked") {
		return fmt.Errorf("invalid Transfer-Encoding request header: %q", vv)
	}
	if vv := h["Connection"]; len(vv) > 0 && (len(vv) > 1 || vv[0] != "" && !asciiEqualFold(vv[0], "close") && !asciiEqualFold(vv[0], "keep-alive")) {
		return fmt.Errorf("invalid Connection request header: %q", vv)
	}
	// [eidolon] TE may only be "trailers" (RFC 9113 section 8.2.2); the
	// name is matched in any case because it is sent lowercased.
	for k, vv := range h {
		if !asciiEqualFold(k, "te") {
			continue
		}
		for _, v := range vv {
			if !asciiEqualFold(v, "trailers") {
				return fmt.Errorf("invalid TE request header: %q", vv)
			}
		}
	}
	return nil
}

func commaSeparatedTrailers(trailer map[string][]string) (string, error) {
	keys := make([]string, 0, len(trailer))
	for k := range trailer {
		k = CanonicalHeader(k)
		switch k {
		case "Transfer-Encoding", "Trailer", "Content-Length":
			return "", fmt.Errorf("invalid Trailer key %q", k)
		}
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		sort.Strings(keys)
		return strings.Join(keys, ","), nil
	}
	return "", nil
}

// validPseudoPath reports whether v is a valid :path pseudo-header
// value. It must be either:
//
//   - a non-empty string starting with '/'
//   - the string '*', for OPTIONS requests.
//
// For now this is only used a quick check for deciding when to clean
// up Opaque URLs before sending requests from the Transport.
// See golang.org/issue/16847
//
// We used to enforce that the path also didn't start with "//", but
// Google's GFE accepts such paths and Chrome sends them, so ignore
// that part of the spec. See golang.org/issue/19103.
func validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/') || v == "*"
}

// [eidolon] split reports whether Cookie is split into crumbs, as it is
// outside exact mode.
func validateHeaders(hdrs map[string][]string, split bool) string {
	for k, vv := range hdrs {
		if !httpguts.ValidHeaderFieldName(k) && k != ":protocol" {
			return fmt.Sprintf("name %q", k)
		}
		for _, v := range vv {
			// [eidolon] Leading and trailing whitespace is forbidden too
			// (RFC 9113 section 8.2.1), in every field sent: a split
			// Cookie is checked crumb by crumb.
			edges := []string{v}
			if split && asciiEqualFold(k, "cookie") {
				edges = cookieCrumbs(v)
			}
			if !httpguts.ValidHeaderFieldValue(v) || slices.ContainsFunc(edges, untrimmed) {
				// Don't include the value in the error,
				// because it may be sensitive.
				return fmt.Sprintf("value for header %q", k)
			}
		}
	}
	return ""
}

// [eidolon] untrimmed reports whether v starts or ends with SP or HTAB.
func untrimmed(v string) bool {
	return v != strings.Trim(v, " \t")
}

// [eidolon] cookieCrumbs splits a Cookie value as Chrome does (quiche
// HpackEncoder::CookieToCrumbs): without the whitespace at both ends,
// at each ';', and without one space after it. Empty crumbs are kept, the
// last one included. A crumb can still start or end with whitespace, as
// "a=1 ; b" gives "a=1 "; validateHeaders refuses it.
func cookieCrumbs(v string) []string {
	v = strings.Trim(v, " \t")
	var out []string
	for {
		p := strings.IndexByte(v, ';')
		if p < 0 {
			return append(out, v)
		}
		out = append(out, v[:p])
		v = v[p+1:]
		if len(v) > 0 && v[0] == ' ' {
			v = v[1:]
		}
	}
}

// checkExact checks the framing of exact fields before anything is sent:
// at most one Host, which replaces host, and a Content-Length, if any, equal
// to the body length. Nothing is corrected.
func checkExact(exact []order.Field, contentLength int64, host *string) error {
	var hosts, lengths int
	for _, f := range exact {
		switch {
		case asciiEqualFold(f.Name, "host"):
			hosts++
			*host = f.Value
		case asciiEqualFold(f.Name, "content-length"):
			lengths++
			if n, err := strconv.ParseInt(f.Value, 10, 64); err != nil || n != contentLength || !digits(f.Value) {
				return fmt.Errorf("exact headers: content-length %q does not match the body", f.Value)
			}
		}
	}
	if hosts > 1 || lengths > 1 {
		return errors.New("exact headers: Host or Content-Length repeated")
	}
	return nil
}

// digits reports whether s has digits only, as the Content-Length syntax
// (RFC 9110 section 8.6, 1*DIGIT); ParseInt also takes a sign, and refuses
// an empty s.
func digits(s string) bool {
	return strings.Trim(s, "0123456789") == ""
}

// shouldSendReqContentLength reports whether we should send
// a "content-length" request header. This logic is basically a copy of the net/http
// transferWriter.shouldSendContentLength.
// The contentLength is the corrected contentLength (so 0 means actually 0, not unknown).
// -1 means unknown.
func shouldSendReqContentLength(method string, contentLength int64) bool {
	if contentLength > 0 {
		return true
	}
	if contentLength < 0 {
		return false
	}
	// For zero bodies, whether we send a content-length depends on the method.
	// It also kinda doesn't matter for http2 either way, with END_STREAM.
	// Only POST and PUT, as Chrome (HttpNetworkTransaction::BuildRequestHeaders).
	switch method {
	case "POST", "PUT":
		return true
	default:
		return false
	}
}

// ServerRequestParam is parameters to NewServerRequest.
type ServerRequestParam struct {
	Method                  string
	Scheme, Authority, Path string
	Protocol                string
	Header                  map[string][]string
}

// ServerRequestResult is the result of NewServerRequest.
type ServerRequestResult struct {
	// Various http.Request fields.
	Host       string
	URL        *url.URL
	RequestURI string
	Trailer    map[string][]string

	NeedsContinue bool // client provided an "Expect: 100-continue" header

	// If the request should be rejected, this is a short string suitable for passing
	// to the http2 package's CountError function.
	// It might be a bit odd to return errors this way rather than returning an error,
	// but this ensures we don't forget to include a CountError reason.
	InvalidReason string
}

func NewServerRequest(rp ServerRequestParam) ServerRequestResult {
	needsContinue := httpguts.HeaderValuesContainsToken(rp.Header["Expect"], "100-continue")
	if needsContinue {
		delete(rp.Header, "Expect")
	}
	// Merge Cookie headers into one "; "-delimited value.
	if cookies := rp.Header["Cookie"]; len(cookies) > 1 {
		rp.Header["Cookie"] = []string{strings.Join(cookies, "; ")}
	}

	// Setup Trailers
	var trailer map[string][]string
	for _, v := range rp.Header["Trailer"] {
		for _, key := range strings.Split(v, ",") {
			key = textproto.CanonicalMIMEHeaderKey(textproto.TrimString(key))
			switch key {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				// Bogus. (copy of http1 rules)
				// Ignore.
			default:
				if trailer == nil {
					trailer = make(map[string][]string)
				}
				trailer[key] = nil
			}
		}
	}
	delete(rp.Header, "Trailer")

	authority := rp.Authority
	if host := rp.Header["Host"]; len(host) == 1 {
		// HTTP/2 and HTTP/3 permit the Host header to be present,
		// but it must match the :authority pseudo-header.
		if authority == "" {
			authority = host[0]
		} else if host[0] != authority {
			return ServerRequestResult{
				InvalidReason: "authority_host_mismatch",
			}
		}
		delete(rp.Header, "Host")
	} else if len(host) > 1 {
		// HTTP/1.1 rejects any request containing more than one Host header.
		// HTTP/2 and HTTP/3 don't use the Host header, but reject multiple anyway.
		return ServerRequestResult{
			InvalidReason: "multiple_host_headers",
		}
	}

	// "':authority' MUST NOT include the deprecated userinfo subcomponent
	// for "http" or "https" schemed URIs."
	// https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1-2.3.8
	if strings.IndexByte(authority, '@') != -1 && (rp.Scheme == "http" || rp.Scheme == "https") {
		return ServerRequestResult{
			InvalidReason: "userinfo_in_authority",
		}
	}

	if authority != "" && !httpguts.ValidHostHeader(authority) {
		return ServerRequestResult{
			InvalidReason: "invalid_authority",
		}
	}

	var url_ *url.URL
	var requestURI string
	if rp.Method == "CONNECT" && rp.Protocol == "" {
		url_ = &url.URL{Host: authority}
		requestURI = authority // mimic HTTP/1 server behavior
	} else {
		// "[The :path] pseudo-header field MUST NOT be empty [...]"
		// https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1-2.4.2
		if rp.Path == "" || (rp.Path[0] != '/' && rp.Path != "*") {
			return ServerRequestResult{
				InvalidReason: "bad_path",
			}
		}

		var err error
		url_, err = url.ParseRequestURI(rp.Path)
		if err != nil {
			return ServerRequestResult{
				InvalidReason: "bad_path",
			}
		}
		requestURI = rp.Path
	}

	return ServerRequestResult{
		Host:          authority,
		URL:           url_,
		NeedsContinue: needsContinue,
		RequestURI:    requestURI,
		Trailer:       trailer,
	}
}
