package httpcommon

import (
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// An empty body states its length for POST and PUT only, as Chrome.
func TestShouldSendReqContentLengthChrome(t *testing.T) {
	for method, want := range map[string]bool{
		"POST": true, "PUT": true, "PATCH": false, "DELETE": false, "GET": false, "OPTIONS": false,
	} {
		if got := shouldSendReqContentLength(method, 0); got != want {
			t.Errorf("%s: got %v, want %v", method, got, want)
		}
	}
}

// An exact content-length is 1*DIGIT equal to the body length.
func TestCheckExactContentLength(t *testing.T) {
	for v, ok := range map[string]bool{
		"7": true, "007": true, "+7": false, "-7": false, "": false, "7 ": false, "8": false,
	} {
		var host string
		err := checkExact([]order.Field{{Name: "Content-Length", Value: v}}, 7, &host)
		if (err == nil) != ok {
			t.Errorf("%q: err = %v, want ok %v", v, err, ok)
		}
	}
}
