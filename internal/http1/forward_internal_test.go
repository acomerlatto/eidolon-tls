package http1

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// forwardHead returns the head of a request to a proxy that forwards it.
func forwardHead(t *testing.T, req *http.Request, fwd *Forward, o []string) string {
	t.Helper()
	if o != nil {
		req = req.WithContext(order.WithOrder(req.Context(), order.Order{Header: o}))
	}
	head, err := encodeHead(req, Spelling{"proxy-connection": "Proxy-Connection"}, fwd)
	if err != nil {
		t.Fatal(err)
	}
	return head
}

// The request line carries the absolute URL, without credentials or
// fragment; Connection goes as Proxy-Connection in its place, and
// Proxy-Authorization after the fields Chrome sets before it.
func TestForward(t *testing.T) {
	auth := &Forward{Authorization: "Basic dTpw"}
	o := []string{"host", "connection", "content-length", "cache-control", "pragma", "user-agent", "accept"}
	for _, tt := range []struct {
		name   string
		method string
		url    string
		header http.Header
		fwd    *Forward
		want   string
	}{
		{"navigation", "GET", "http://u:p@a.test/x?y#z", http.Header{"Connection": {"keep-alive"}, "User-Agent": {"UA"}}, auth,
			"GET http://a.test/x?y HTTP/1.1\r\nHost: a.test\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic dTpw\r\nUser-Agent: UA\r\n\r\n"},
		{"after framing and cache", "POST", "http://a.test:8080/", http.Header{"Connection": {"keep-alive"}, "Cache-Control": {"max-age=0"}, "Pragma": {"no-cache"}, "Accept": {"*/*"}}, auth,
			"POST http://a.test:8080/ HTTP/1.1\r\nHost: a.test:8080\r\nProxy-Connection: keep-alive\r\nContent-Length: 0\r\nCache-Control: max-age=0\r\nPragma: no-cache\r\nProxy-Authorization: Basic dTpw\r\nAccept: */*\r\n\r\n"},
		{"last", "GET", "http://a.test/", http.Header{"Connection": {"close"}}, auth,
			"GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\nProxy-Connection: close\r\nProxy-Authorization: Basic dTpw\r\n\r\n"},
		{"the request's own", "GET", "http://a.test/", http.Header{"Proxy-Authorization": {"Bearer x"}, "Accept": {"*/*"}}, auth,
			"GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\nAccept: */*\r\nProxy-Authorization: Bearer x\r\n\r\n"},
		{"no credentials", "GET", "http://a.test/", http.Header{"Connection": {"keep-alive"}}, &Forward{},
			"GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\nProxy-Connection: keep-alive\r\n\r\n"},
		{"international name", "GET", "http://bücher.test/", nil, &Forward{},
			"GET http://xn--bcher-kva.test/ HTTP/1.1\r\nHost: xn--bcher-kva.test\r\n\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header = tt.header
			if got := forwardHead(t, req, tt.fwd, o); got != tt.want {
				t.Errorf("head %q\nwant %q", got, tt.want)
			}
		})
	}
	// A body of unknown length is chunked, its Transfer-Encoding before
	// Proxy-Authorization.
	req, _ := http.NewRequest("POST", "http://a.test/", io.NopCloser(strings.NewReader("x")))
	req.Header = http.Header{"Accept": {"*/*"}}
	want := "POST http://a.test/ HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\nProxy-Authorization: Basic dTpw\r\nAccept: */*\r\n\r\n"
	if got := forwardHead(t, req, auth, []string{"host", "transfer-encoding", "accept"}); got != want {
		t.Errorf("chunked head %q\nwant %q", got, want)
	}
}

// The absolute URL takes the host of the URL, not a Host override, and
// exact mode takes the absolute URL only.
func TestForwardHost(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://a.test/p", nil)
	req.Host = "b.test"
	if got := forwardHead(t, req, &Forward{Authorization: "Basic dTpw"}, nil); !strings.HasPrefix(got, "GET http://a.test/p HTTP/1.1\r\nHost: b.test\r\n") {
		t.Errorf("head %q", got)
	}
	exact := req.WithContext(order.WithExact(req.Context(), []order.Field{{Name: "Host", Value: "a.test"}, {Name: "Connection", Value: "keep-alive"}}))
	if got := forwardHead(t, exact, &Forward{Authorization: "Basic dTpw"}, nil); got != "GET http://a.test/p HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive\r\n\r\n" {
		t.Errorf("exact head %q", got)
	}
	for _, host := range []string{"a b", ""} {
		req.URL.Host = host
		if _, err := encodeHead(req, nil, &Forward{}); err == nil {
			t.Errorf("URL host %q accepted", host)
		}
	}
}
