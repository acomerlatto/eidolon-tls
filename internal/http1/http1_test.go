package http1_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
	"github.com/acomerlatto/eidolon-tls/internal/order"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

var spell = http1.Spelling{"sec-ch-ua": "sec-ch-ua", "x-mixed": "X-mIxEd"}

// newRequest builds a GET with a profile-like order and repeated values.
func newRequest(t *testing.T, ctx context.Context) *http.Request {
	t.Helper()
	ctx = order.WithOrder(ctx, order.Order{Header: []string{"host", "connection", "sec-ch-ua", "user-agent", "accept", "x-multi"}})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/path?q=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "eidolon-test")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="155"`)
	req.Header["X-Multi"] = []string{"1", "2"}
	req.Header.Set("X-Mixed", "m")
	req.Header.Set("A-Last", "z")
	return req
}

// Listed names in order, one line per value, then the unlisted names in
// alphabetical order; spelling from the table or canonical.
const wantRequest = "GET /path?q=1 HTTP/1.1\r\n" +
	"Host: example.com\r\n" +
	"Connection: keep-alive\r\n" +
	"sec-ch-ua: \"Chromium\";v=\"155\"\r\n" +
	"User-Agent: eidolon-test\r\n" +
	"Accept: */*\r\n" +
	"X-Multi: 1\r\n" +
	"X-Multi: 2\r\n" +
	"A-Last: z\r\n" +
	"X-mIxEd: m\r\n" +
	"\r\n"

func TestWriteRequest(t *testing.T) {
	var buf bytes.Buffer
	if err := http1.WriteRequest(&buf, newRequest(t, context.Background()), spell); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != wantRequest {
		t.Fatalf("got:\n%s\nwant:\n%s", got, wantRequest)
	}
}

func TestWriteRequestDefaultOrder(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Zeta", "1")
	req.Header.Set("Accept", "2")
	req.Host = "other.example:8080"
	var buf bytes.Buffer
	if err := http1.WriteRequest(&buf, req, nil); err != nil {
		t.Fatal(err)
	}
	want := "GET / HTTP/1.1\r\nHost: other.example:8080\r\nAccept: 2\r\nZeta: 1\r\n\r\n"
	if got := buf.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWriteRequestBody(t *testing.T) {
	ctx := order.WithOrder(context.Background(), order.Order{Header: []string{"host", "content-length", "content-type"}})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://example.com/submit", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	var buf bytes.Buffer
	if err := http1.WriteRequest(&buf, req, nil); err != nil {
		t.Fatal(err)
	}
	want := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 7\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
	if got := buf.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Invalid requests are refused before any byte is written.
func TestWriteRequestRejects(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*http.Request)
		spell  http1.Spelling
	}{
		{name: "CRLF in value", modify: func(r *http.Request) { r.Header.Set("X-A", "v\r\nX-Injected: 1") }},
		{name: "LF in value", modify: func(r *http.Request) { r.Header["X-A"] = []string{"v\nw"} }},
		{name: "invalid name", modify: func(r *http.Request) { r.Header["X A"] = []string{"v"} }},
		{name: "CRLF in Host", modify: func(r *http.Request) { r.Host = "example.com\r\nX: 1" }},
		{name: "space in method", modify: func(r *http.Request) { r.Method = "GET /x" }},
		{name: "Content-Length in Header", modify: func(r *http.Request) { r.Header.Set("Content-Length", "5") }},
		{name: "Transfer-Encoding in Header", modify: func(r *http.Request) { r.Header.Set("Transfer-Encoding", "chunked") }},
		{name: "body of unknown length", modify: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("x"))
			r.ContentLength = -1
		}},
		{name: "spelling of another name", spell: http1.Spelling{"accept": "Accept-Language"}, modify: func(r *http.Request) { r.Header.Set("Accept", "1") }},
		{name: "spelling with CRLF", spell: http1.Spelling{"accept": "Accept\r\n"}, modify: func(r *http.Request) { r.Header.Set("Accept", "1") }},
		// RFC 9112 section 3.2.3: CONNECT needs authority-form; tunnels are
		// outside phase 1.
		{name: "CONNECT", modify: func(r *http.Request) { r.Method = http.MethodConnect }},
		{name: "trailers", modify: func(r *http.Request) { r.Trailer = http.Header{"X-T": nil} }},
		{name: "Upgrade", modify: func(r *http.Request) { r.Header.Set("Upgrade", "websocket") }},
		{name: "upgrade non-canonical", modify: func(r *http.Request) { r.Header["upgrade"] = []string{"h2c"} }},
		// The query is percent-encoded before the engine; raw bytes outside
		// the grammar are refused, not sent.
		{name: "non-ASCII in query", modify: func(r *http.Request) { r.URL.RawQuery = "q=\u00e7" }},
		{name: "control in query", modify: func(r *http.Request) { r.URL.RawQuery = "q=\x01" }},
		{name: "DEL in query", modify: func(r *http.Request) { r.URL.RawQuery = "q=\x7f" }},
		// RFC 9110 section 5.5 grammar: no leading or trailing whitespace.
		{name: "leading space", modify: func(r *http.Request) { r.Header.Set("X-A", " a") }},
		{name: "trailing tab", modify: func(r *http.Request) { r.Header.Set("X-A", "a\t") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
			tt.modify(req)
			var buf bytes.Buffer
			if err := http1.WriteRequest(&buf, req, tt.spell); err == nil {
				t.Fatal("no error")
			}
			if buf.Len() != 0 {
				t.Fatalf("wrote %q", buf.String())
			}
		})
	}
}

func roundTrip(t *testing.T, conn net.Conn, req *http.Request) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	resp, err := http1.NewConn(conn).RoundTrip(req, spell)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 1 || string(body) != "ok" {
		t.Fatalf("got %s %s %q", resp.Proto, resp.Status, body)
	}
}

// The lab receives the request byte for byte, over http:// and over TLS
// with ALPN http/1.1.
func TestRoundTripOnTheWire(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{Plain: true})
		conn, err := net.Dial("tcp", srv.Addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		roundTrip(t, conn, newRequest(t, context.Background()))
		if got := string(srv.NextConn(t).Bytes()); got != wantRequest {
			t.Fatalf("lab got:\n%s\nwant:\n%s", got, wantRequest)
		}
	})
	t.Run("TLS", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := tlsdial.Dial(ctx, "tcp", srv.Addr, tlsdial.Config{
			Spec: func() (*utls.ClientHelloSpec, error) {
				spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
				return &spec, err
			},
			TLS: &utls.Config{ServerName: lab.ServerName, RootCAs: srv.RootCAs},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if p := conn.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
			t.Fatalf("ALPN = %q", p)
		}
		req := newRequest(t, ctx)
		req.URL.Scheme = "https"
		roundTrip(t, conn, req)
		if got := string(srv.NextConn(t).Bytes()); got != wantRequest {
			t.Fatalf("lab got:\n%s\nwant:\n%s", got, wantRequest)
		}
	})
}

// 1xx responses are skipped until the final response.
func TestRoundTripSkipsInformational(t *testing.T) {
	srv := lab.Start(t, lab.Options{Plain: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		io.WriteString(w, "ok")
	})})
	conn, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, newRequest(t, context.Background()))
}

// The body must match ContentLength: a longer body is an error, not
// silently truncated.
func TestWriteRequestBodyLongerThanContentLength(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("abcdef"))
	req.ContentLength = 3
	var buf bytes.Buffer
	if err := http1.WriteRequest(&buf, req, nil); err == nil {
		t.Fatalf("no error; wrote %q", buf.String())
	}
}

// Header normalizations shared with the H2 engine.
func TestWriteRequestNormalizes(t *testing.T) {
	tests := []struct {
		name   string
		method string
		header http.Header
		want   string
	}{
		// RFC 6265 section 5.4: one Cookie field, values joined with "; ",
		// keys merged in byte order.
		{name: "one cookie line", header: http.Header{"Cookie": {"a=1", "b=2"}, "cookie": {"c=3"}},
			want: "Cookie: a=1; b=2; c=3\r\n"},
		// RFC 9110 section 8.6: Content-Length for methods that define
		// content, as the H2 engine does.
		{name: "POST without body", method: http.MethodPost, want: "Content-Length: 0\r\n"},
		{name: "PUT without body", method: http.MethodPut, want: "Content-Length: 0\r\n"},
		{name: "PATCH without body", method: http.MethodPatch, want: "Content-Length: 0\r\n"},
		{name: "GET without body", method: http.MethodGet, want: ""},
		{name: "DELETE without body", method: http.MethodDelete, want: ""},
		// User-Agent as in the H2 engine and net/http: one value, and an
		// empty one omits the field.
		{name: "repeated User-Agent", header: http.Header{"User-Agent": {"a", "b"}}, want: "User-Agent: a\r\n"},
		{name: "empty User-Agent", header: http.Header{"User-Agent": {""}}, want: ""},
		{name: "cookie keeps its spaces", header: http.Header{"Cookie": {"a=1; "}}, want: "Cookie: a=1; \r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "http://example.com/", nil)
			if tt.header != nil {
				req.Header = tt.header
			}
			var buf bytes.Buffer
			if err := http1.WriteRequest(&buf, req, nil); err != nil {
				t.Fatal(err)
			}
			method := tt.method
			if method == "" {
				method = http.MethodGet
			}
			want := method + " / HTTP/1.1\r\nHost: example.com\r\n" + tt.want + "\r\n"
			if got := buf.String(); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}
