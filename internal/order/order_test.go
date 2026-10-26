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
			name:   "nil lists keep the engine order",
			order:  Order{},
			fields: []Field{{":authority", "h"}, {":method", "GET"}, {"z", "1"}, {"a", "2"}},
			want:   []Field{{":authority", "h"}, {":method", "GET"}, {"z", "1"}, {"a", "2"}},
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
