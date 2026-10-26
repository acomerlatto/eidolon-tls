// Package order computes the order of header fields, shared by the HTTP/2
// and HTTP/1.1 engines. The order travels in the request context, never as
// a control header.
package order

import (
	"cmp"
	"context"
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
	// ones in alphabetical order. Nil keeps the engine's order.
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

// sortByList moves the listed names to the front, in list order. The others
// follow in alphabetical order if alphabetical is set, else in their
// original order.
func sortByList(fields []Field, list []string, alphabetical bool) {
	if list == nil {
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
