package eidolon

import (
	"context"

	"github.com/acomerlatto/eidolon-tls/internal/fetch"
)

// FetchDest is the destination of a request in the Fetch standard, sent in
// Sec-Fetch-Dest: what the browser fetches it for. With a profile, it
// chooses the headers of the request; without one, nothing uses it.
//
// The constants are the destinations whose headers come from a capture.
// The other values Sec-Fetch-Dest can send, such as "font", "iframe" or
// "worker", are accepted too.
type FetchDest string

const (
	// FetchDocument is a navigation: a link followed, an address typed, a
	// form submitted.
	FetchDocument FetchDest = "document"
	// FetchEmpty is a request of fetch() or XMLHttpRequest.
	FetchEmpty FetchDest = "empty"
	// FetchStyle is a stylesheet.
	FetchStyle FetchDest = "style"
	// FetchScript is a script.
	FetchScript FetchDest = "script"
	// FetchImage is an image.
	FetchImage FetchDest = "image"
)

// WithFetchDest returns a context that sends a request as the destination
// dest. With a profile, a request with a destination Sec-Fetch-Dest cannot
// send fails before it is sent. A redirect keeps the destination of the
// first request, as Chrome does.
//
// Without it, the destination comes from the request: its Sec-Fetch-Dest,
// then its Sec-Fetch-Mode (navigate is a FetchDocument, any other mode a
// FetchEmpty), then an Accept of an API such as application/json or a bare
// */* (FetchEmpty), then the method: GET, HEAD and the POST of a form
// (application/x-www-form-urlencoded or multipart/form-data) are a
// FetchDocument, anything else a FetchEmpty.
func WithFetchDest(ctx context.Context, dest FetchDest) context.Context {
	return fetch.WithDest(ctx, string(dest))
}
