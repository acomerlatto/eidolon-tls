package eidolon

import (
	"context"

	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// Order lists header names in the order they are sent, in both HTTP/2 and
// HTTP/1.1. Names are compared case-insensitively; a name listed twice keeps
// its first position, and a listed name without a value in the request
// creates nothing.
type Order struct {
	// Pseudo orders the HTTP/2 pseudo-headers (":method", ":authority",
	// ":scheme", ":path"). Nil keeps the engine's order.
	Pseudo []string
	// Header orders the regular headers. Names not listed follow in
	// alphabetical order. Nil keeps the default order.
	Header []string
}

// WithOrder returns a context that carries o for the requests made with it.
// The lists are copied. The order is never sent as a header.
func WithOrder(ctx context.Context, o Order) context.Context {
	return order.WithOrder(ctx, order.Order(o))
}
