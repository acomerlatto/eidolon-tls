package http1

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// An empty Read of a probed body keeps the probed byte for the next one.
func TestProbedBodyEmptyRead(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", nil)
	req.Body = io.NopCloser(strings.NewReader("abc"))
	req, err := probeBody(req)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := req.Body.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty Read = %d, %v", n, err)
	}
	if got, err := io.ReadAll(req.Body); string(got) != "abc" || err != nil {
		t.Fatalf("got %q, %v", got, err)
	}
}
