package eidolon

import (
	"context"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/fetch"
)

// WithFetchDest hands the destination to the transport as given.
func TestWithFetchDest(t *testing.T) {
	for _, d := range []FetchDest{FetchDocument, FetchEmpty, FetchStyle, FetchScript, FetchImage, "font"} {
		if got, ok := fetch.DestFromContext(WithFetchDest(context.Background(), d)); !ok || got != string(d) || !fetch.Known(got) {
			t.Errorf("WithFetchDest(%q) carries %q, %v", d, got, ok)
		}
	}
}
