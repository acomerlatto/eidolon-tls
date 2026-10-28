// Package fetch tells what a browser would fetch a request for: its
// destination in the Fetch standard, sent in Sec-Fetch-Dest. A profile
// chooses the headers of a request by it.
package fetch

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// Destinations of the Fetch standard as Sec-Fetch-Dest sends them, with
// "empty" for none, and those Chromium adds.
var dests = []string{
	"audio", "audioworklet", "document", "embed", "empty", "fencedframe",
	"font", "frame", "iframe", "image", "json", "manifest", "object",
	"paintworklet", "report", "script", "serviceworker", "sharedworker",
	"style", "track", "video", "webidentity", "websocket", "worker", "xslt",
}

// Known reports whether dest is a destination Sec-Fetch-Dest can send.
func Known(dest string) bool {
	_, ok := slices.BinarySearch(dests, dest)
	return ok
}

type destKey struct{}

// WithDest returns a context carrying the destination of a request.
func WithDest(ctx context.Context, dest string) context.Context {
	return context.WithValue(ctx, destKey{}, dest)
}

// DestFromContext returns the destination carried by ctx, if any.
func DestFromContext(ctx context.Context) (string, bool) {
	d, ok := ctx.Value(destKey{}).(string)
	return d, ok
}

// Dest returns the destination of req: the one its context carries, which
// must be known, otherwise the one its form suggests (inference as in
// httpcloak, A4):
//
//   - a known Sec-Fetch-Dest of the header;
//   - Sec-Fetch-Mode navigate gives "document", any other mode "empty";
//   - an Accept of an API, such as application/json or a bare */*, gives
//     "empty", unless it lists text/html, as a navigation does;
//   - GET and HEAD give "document", as a link followed;
//   - POST of a form (application/x-www-form-urlencoded or
//     multipart/form-data) gives "document", as a form submitted; HTML
//     forms send no other method;
//   - anything else gives "empty", as fetch() would send it.
func Dest(req *http.Request) (string, error) {
	if d, ok := DestFromContext(req.Context()); ok {
		if !Known(d) {
			return "", fmt.Errorf("unknown fetch destination %q", d)
		}
		return d, nil
	}
	if d := strings.ToLower(req.Header.Get("Sec-Fetch-Dest")); Known(d) {
		return d, nil
	}
	if m := req.Header.Get("Sec-Fetch-Mode"); m != "" {
		if strings.EqualFold(m, "navigate") {
			return "document", nil
		}
		return "empty", nil
	}
	if apiAccept(req.Header.Get("Accept")) {
		return "empty", nil
	}
	switch req.Method {
	case "", http.MethodGet, http.MethodHead:
		return "document", nil
	case http.MethodPost:
		switch mediaType(req.Header.Get("Content-Type")) {
		case "application/x-www-form-urlencoded", "multipart/form-data":
			return "document", nil
		}
	}
	return "empty", nil
}

// apiAccept reports whether accept asks for what an API answers.
func apiAccept(accept string) bool {
	if strings.TrimSpace(accept) == "*/*" {
		return true
	}
	api := false
	for t := range strings.SplitSeq(accept, ",") {
		switch t = mediaType(t); {
		case t == "text/html", t == "application/xhtml+xml":
			return false
		case t == "application/json", t == "application/xml", t == "text/plain",
			t == "application/octet-stream",
			strings.HasSuffix(t, "+json"), strings.HasSuffix(t, "+xml"):
			api = true
		}
	}
	return api
}

// mediaType returns the media type of a header value, without parameters,
// in lowercase; "" if it has none.
func mediaType(v string) string {
	t, _, _ := strings.Cut(v, ";")
	return strings.ToLower(strings.TrimSpace(t))
}
