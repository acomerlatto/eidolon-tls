// Package order computes the order of header fields, shared by the HTTP/2
// and HTTP/1.1 engines. The order travels in the request context, never as
// a control header.
package order

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"strings"
)

// Field is one header field as the engine emits it.
type Field struct {
	Name, Value string
}

// Order lists header names in the order they must be sent. Names are
// compared case-insensitively; a name listed twice keeps its first position.
type Order struct {
	// Pseudo orders the HTTP/2 pseudo-headers (":method", ...). Nil keeps
	// the engine's order.
	Pseudo []string
	// Header orders the regular headers. Names not listed follow the listed
	// ones in alphabetical order; nil sorts them all alphabetically, so the
	// order never depends on map iteration.
	Header []string
}

type ctxKey struct{}

// WithOrder returns a context carrying o. The lists are copied.
func WithOrder(ctx context.Context, o Order) context.Context {
	o.Pseudo = slices.Clone(o.Pseudo)
	o.Header = slices.Clone(o.Header)
	return context.WithValue(ctx, ctxKey{}, &o)
}

// FromContext returns the order carried by ctx, or nil.
func FromContext(ctx context.Context) *Order {
	o, _ := ctx.Value(ctxKey{}).(*Order)
	return o
}

// Keys of Request.Header that carry the order of a request, with the
// strings of fhttp and the sardanioss x/net fork. The ':' makes them invalid
// field names, so an engine refuses them rather than sending them.
const (
	HeaderKey = "Header-Order:"
	PseudoKey = "PHeader-Order:"
)

// FromHeader returns the order carried by the keys of h, or nil if it has
// neither.
func FromHeader(h http.Header) *Order {
	pseudo, okP := h[PseudoKey]
	header, okH := h[HeaderKey]
	if !okP && !okH {
		return nil
	}
	return &Order{Pseudo: slices.Clone(pseudo), Header: slices.Clone(header)}
}

// WithoutKeys returns h without the order keys: a copy if it has one, else
// h itself. h is never modified.
func WithoutKeys(h http.Header) http.Header {
	_, okP := h[PseudoKey]
	_, okH := h[HeaderKey]
	if !okP && !okH {
		return h
	}
	out := h.Clone()
	delete(out, PseudoKey)
	delete(out, HeaderKey)
	return out
}

// Merge combines orders by precedence, highest first (request, client,
// profile). Each list leads with the names of the first order that has
// one; the names of the following ones, not yet listed, come next in their
// own order. Nil orders are skipped; Merge returns nil if all are nil.
func Merge(orders ...*Order) *Order {
	var out *Order
	for _, o := range orders {
		if o == nil {
			continue
		}
		if out == nil {
			out = &Order{}
		}
		if o.Pseudo != nil {
			out.Pseudo = append(slices.Clip(out.Pseudo), o.Pseudo...)
		}
		if o.Header != nil {
			out.Header = append(slices.Clip(out.Header), o.Header...)
		}
	}
	return out
}

type exactKey struct{}

// WithExact returns a context carrying the exact header fields of a
// request: they replace the regular headers, in this order, with the names
// as given. An empty list leaves ctx as it is. The list is copied.
func WithExact(ctx context.Context, fields []Field) context.Context {
	if len(fields) == 0 {
		return ctx
	}
	return context.WithValue(ctx, exactKey{}, slices.Clone(fields))
}

// ExactFromContext returns the exact header fields carried by ctx, or nil.
func ExactFromContext(ctx context.Context) []Field {
	f, _ := ctx.Value(exactKey{}).([]Field)
	return f
}

// Sort returns fields with the pseudo-headers first, each group in the
// order of o. Values of the same name keep their relative order. fields is
// not modified.
func (o *Order) Sort(fields []Field) []Field {
	var pseudo, regular []Field
	for _, f := range fields {
		if strings.HasPrefix(f.Name, ":") {
			pseudo = append(pseudo, f)
		} else {
			regular = append(regular, f)
		}
	}
	sortByList(pseudo, o.Pseudo, false)
	sortByList(regular, o.Header, true)
	return append(pseudo, regular...)
}

// SortPseudo returns fields with the pseudo-headers first, in the order of
// o, and the regular fields after them as given: the order of exact mode.
// fields is not modified.
func (o *Order) SortPseudo(fields []Field) []Field {
	var pseudo, regular []Field
	for _, f := range fields {
		if strings.HasPrefix(f.Name, ":") {
			pseudo = append(pseudo, f)
		} else {
			regular = append(regular, f)
		}
	}
	sortByList(pseudo, o.Pseudo, false)
	return append(pseudo, regular...)
}

// sortByList moves the listed names to the front, in list order. The others
// follow in alphabetical order if alphabetical is set, else in their
// original order.
func sortByList(fields []Field, list []string, alphabetical bool) {
	if list == nil && !alphabetical {
		return
	}
	rank := make(map[string]int, len(list))
	for i, name := range list {
		name = strings.ToLower(name)
		if _, ok := rank[name]; !ok {
			rank[name] = i
		}
	}
	unlisted := len(list)
	slices.SortStableFunc(fields, func(a, b Field) int {
		an, bn := strings.ToLower(a.Name), strings.ToLower(b.Name)
		ra, ok := rank[an]
		if !ok {
			ra = unlisted
		}
		rb, ok := rank[bn]
		if !ok {
			rb = unlisted
		}
		if c := cmp.Compare(ra, rb); c != 0 || ra != unlisted || !alphabetical {
			return c
		}
		return strings.Compare(an, bn)
	})
}
