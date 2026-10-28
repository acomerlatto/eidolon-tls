package eidolon

import (
	"context"

	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// HeaderOrderKey and PHeaderOrderKey are keys of Request.Header that set the
// order of a request, as in fhttp (tls-client) and the sardanioss x/net fork:
//
//	req.Header[eidolon.HeaderOrderKey] = []string{"accept", "user-agent", "accept-language"}
//	req.Header[eidolon.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
//
// HeaderOrderKey orders the regular headers and PHeaderOrderKey the HTTP/2
// pseudo-headers. Both are optional and are never sent: the transport reads
// them from a copy of Request.Header without changing the caller's.
// http.Client copies them to a redirected request, so the order follows it.
// See Order for how names are compared and completed.
const (
	HeaderOrderKey  = order.HeaderKey
	PHeaderOrderKey = order.PseudoKey
)

// Order lists header names in the order they are sent, in both HTTP/2 and
// HTTP/1.1. Names are compared case-insensitively; a name listed twice keeps
// its first position, and a listed name without a value in the request
// creates nothing.
//
// The order of a request (HeaderOrderKey, PHeaderOrderKey) comes first; the
// names of the client order (WithDefaultOrder) not listed yet follow, then
// the others in alphabetical order. Each list falls back the same way on its
// own: a request without PHeaderOrderKey uses the client's pseudo-header
// order.
type Order struct {
	// Pseudo orders the HTTP/2 pseudo-headers (":method", ":authority",
	// ":scheme", ":path"). Those not listed follow in Chrome's order,
	// ":method", ":authority", ":scheme", ":path".
	Pseudo []string
	// Header orders the regular headers. Names not listed follow in
	// alphabetical order; nil sorts them all alphabetically.
	Header []string
}

// HeaderField is one header field of exact mode.
type HeaderField struct {
	Name, Value string
}

// WithExactHeaders returns a context whose requests send exactly fields as
// their regular headers: in this order, repeated names where they are, and
// nothing else. Request.Header is ignored but for PHeaderOrderKey, and no
// field of the client, the cookie jar or the engines is added: not
// User-Agent, Accept-Encoding, Cookie or Connection. An empty list changes
// nothing. The list is copied.
//
// Over HTTP/1.1 the names are sent spelled as given, and a Host field is
// required. Over HTTP/2 the names are lowercased, Host becomes :authority,
// connection-specific fields such as Connection are left out, and Cookie is
// not split. Pseudo-headers still follow the order (PHeaderOrderKey, then
// the client order).
//
// Framing is checked, never corrected: a body needs a Content-Length field
// with its length over HTTP/1.1, and over HTTP/2 a Content-Length field, if
// any, must match it.
//
// A redirect of such a request fails with ErrExactHeadersRedirect without
// sending anything: http.Client filters credentials out of Header only.
// Use CheckRedirect with http.ErrUseLastResponse and send the next request
// with its own fields.
func WithExactHeaders(ctx context.Context, fields ...HeaderField) context.Context {
	out := make([]order.Field, len(fields))
	for i, f := range fields {
		out[i] = order.Field(f)
	}
	return order.WithExact(ctx, out)
}
