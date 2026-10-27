package order

import (
	"context"
	"slices"
	"testing"
)

func names(fields []Field) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.Name
	}
	return out
}

func TestSort(t *testing.T) {
	tests := []struct {
		name   string
		order  Order
		fields []Field
		want   []Field
	}{
		{
			// Example from section 7 of the specification.
			name:   "listed first, then alphabetical",
			order:  Order{Header: []string{"x-b", "accept", "x-a"}},
			fields: []Field{{"x-z", "z"}, {"X-A", "a"}, {"Accept", "*/*"}, {"x-b", "b"}},
			want:   []Field{{"x-b", "b"}, {"Accept", "*/*"}, {"X-A", "a"}, {"x-z", "z"}},
		},
		{
			name:   "listed name without value creates nothing",
			order:  Order{Header: []string{"user-agent", "accept"}},
			fields: []Field{{"accept", "1"}},
			want:   []Field{{"accept", "1"}},
		},
		{
			name:   "duplicate name in the list keeps the first position",
			order:  Order{Header: []string{"b", "a", "b"}},
			fields: []Field{{"a", "1"}, {"b", "2"}},
			want:   []Field{{"b", "2"}, {"a", "1"}},
		},
		{
			name:   "repeated values keep their order",
			order:  Order{Header: []string{"cookie", "accept"}},
			fields: []Field{{"accept", "1"}, {"cookie", "a=1"}, {"cookie", "b=2"}, {"cookie", "c=3"}},
			want:   []Field{{"cookie", "a=1"}, {"cookie", "b=2"}, {"cookie", "c=3"}, {"accept", "1"}},
		},
		{
			name:   "pseudo-headers first, in their own order",
			order:  Order{Pseudo: []string{":method", ":authority", ":scheme", ":path"}, Header: []string{"accept"}},
			fields: []Field{{":authority", "h"}, {":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {"accept", "1"}},
			want:   []Field{{":method", "GET"}, {":authority", "h"}, {":scheme", "https"}, {":path", "/"}, {"accept", "1"}},
		},
		{
			name:   "nil lists keep the pseudo order and sort the rest alphabetically",
			order:  Order{},
			fields: []Field{{":method", "GET"}, {":authority", "h"}, {"z", "1"}, {"a", "2"}},
			want:   []Field{{":method", "GET"}, {":authority", "h"}, {"a", "2"}, {"z", "1"}},
		},
		{
			name:   "unlisted pseudo-headers keep the engine order after the listed ones",
			order:  Order{Pseudo: []string{":path"}},
			fields: []Field{{":authority", "h"}, {":method", "GET"}, {":path", "/"}},
			want:   []Field{{":path", "/"}, {":authority", "h"}, {":method", "GET"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := slices.Clone(tt.fields)
			got := (&tt.order).Sort(in)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			if !slices.Equal(in, tt.fields) {
				t.Fatalf("input modified: %v", in)
			}
		})
	}
}

func TestContext(t *testing.T) {
	if FromContext(context.Background()) != nil {
		t.Fatal("empty context has an order")
	}
	list := []string{"a", "b"}
	ctx := WithOrder(context.Background(), Order{Header: list})
	list[0] = "changed"
	if got := FromContext(ctx); got == nil || !slices.Equal(got.Header, []string{"a", "b"}) {
		t.Fatalf("FromContext = %+v, want a copy of [a b]", got)
	}
}

func TestSortDeterministic(t *testing.T) {
	o := &Order{Header: []string{"b"}}
	fields := []Field{{"z", "1"}, {"b", "2"}, {"m", "3"}, {"a", "4"}}
	want := names(o.Sort(fields))
	for range 20 {
		if got := names(o.Sort(slices.Clone(fields))); !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestMerge(t *testing.T) {
	request := &Order{Header: []string{"x-b", "accept"}}
	client := &Order{Pseudo: []string{":method", ":authority"}, Header: []string{"user-agent", "accept", "x-a"}}
	// Example from section 7 of the specification: the request leads, the
	// client completes, the rest is alphabetical.
	m := Merge(request, client)
	fields := []Field{{"accept", "1"}, {"x-a", "2"}, {"x-b", "3"}, {"x-z", "4"}, {":authority", "h"}, {":method", "GET"}}
	want := []string{":method", ":authority", "x-b", "accept", "x-a", "x-z"}
	if got := names(m.Sort(fields)); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// Each list falls back on its own: the request has no Pseudo.
	if !slices.Equal(m.Pseudo, client.Pseudo) {
		t.Fatalf("Pseudo = %v, want the client's", m.Pseudo)
	}
	// The inputs are not modified.
	if !slices.Equal(request.Header, []string{"x-b", "accept"}) || !slices.Equal(client.Header, []string{"user-agent", "accept", "x-a"}) {
		t.Fatalf("inputs changed: %v, %v", request.Header, client.Header)
	}
	if Merge(nil, nil) != nil {
		t.Fatal("Merge of nothing is not nil")
	}
	if got := Merge(nil, client); !slices.Equal(got.Header, client.Header) {
		t.Fatalf("Merge(nil, client) = %v", got.Header)
	}
}

func TestSortPseudo(t *testing.T) {
	o := &Order{Pseudo: []string{":method", ":path"}, Header: []string{"a"}}
	fields := []Field{{"x-a", "1"}, {":path", "/"}, {"x-b", "2"}, {":method", "GET"}, {"x-a", "3"}, {"a", "4"}}
	want := []Field{{":method", "GET"}, {":path", "/"}, {"x-a", "1"}, {"x-b", "2"}, {"x-a", "3"}, {"a", "4"}}
	if got := o.SortPseudo(fields); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestWithExact(t *testing.T) {
	ctx := context.Background()
	if WithExact(ctx, nil) != ctx || WithExact(ctx, []Field{}) != ctx {
		t.Fatal("an empty list changed the context")
	}
	fields := []Field{{"x-a", "1"}}
	got := ExactFromContext(WithExact(ctx, fields))
	fields[0].Value = "changed"
	if !slices.Equal(got, []Field{{"x-a", "1"}}) {
		t.Fatalf("got %v, want a copy", got)
	}
	if ExactFromContext(ctx) != nil {
		t.Fatal("exact fields in an empty context")
	}
}
