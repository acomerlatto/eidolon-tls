package eidolon

import (
	"net/http"
	"reflect"
	"testing"
)

// dropSetCookies removes the cookies set again from each Cookie field, keeps
// the order of the others and drops a field left empty.
func TestDropSetCookies(t *testing.T) {
	set := []*http.Cookie{{Name: "c"}, {Name: "d"}}
	for _, tt := range []struct {
		in, want http.Header
	}{
		{http.Header{"Cookie": {"k=0; c=0;", "d=1"}}, http.Header{"Cookie": {"k=0"}}},
		{http.Header{"cookie": {"c=0", "d=1"}, "X-A": {"c=0"}}, http.Header{"X-A": {"c=0"}}},
		{http.Header{"Cookie": {"b=1 ; c = 2; a=3"}}, http.Header{"Cookie": {"b=1; a=3"}}},
	} {
		h := tt.in.Clone()
		dropSetCookies(h, set)
		if !reflect.DeepEqual(h, tt.want) {
			t.Errorf("dropSetCookies(%v) = %v, want %v", tt.in, h, tt.want)
		}
	}
}
