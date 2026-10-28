package http1_test

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
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
		{name: "Transfer-Encoding gzip in Header", modify: func(r *http.Request) { r.Header.Set("Transfer-Encoding", "gzip") }},
		{name: "two Transfer-Encodings in Header", modify: func(r *http.Request) { r.Header["Transfer-Encoding"] = []string{"chunked", "chunked"} }},
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

// A body of unknown length that fails at its first byte writes nothing.
func TestWriteRequestProbeFails(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", nil)
	req.Body = io.NopCloser(iotest.ErrReader(errors.New("boom")))
	var buf bytes.Buffer
	if err := http1.WriteRequest(&buf, req, nil); err == nil || err.Error() != "boom" {
		t.Fatalf("err = %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("wrote %q", buf.String())
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
		// Chrome states the length of an empty POST or PUT only.
		{name: "PATCH without body", method: http.MethodPatch, want: ""},
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

// The body decides the framing: a known length gives Content-Length, an
// unknown one chunked, an empty one none, and the framing fields of Header
// are ignored.
func TestWriteRequestFraming(t *testing.T) {
	tests := []struct {
		name   string
		method string
		body   io.Reader
		length int64
		header http.Header
		want   string
	}{
		{"unknown length", "POST", io.NopCloser(strings.NewReader("hello world")), -1, nil,
			"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\nb\r\nhello world\r\n0\r\n\r\n"},
		{"unknown length of one byte", "POST", io.NopCloser(strings.NewReader("h")), 0, nil,
			"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nh\r\n0\r\n\r\n"},
		{"zero length with a body", "POST", io.NopCloser(strings.NewReader("")), 0, nil,
			"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"},
		{"GET with an empty body", "GET", io.NopCloser(strings.NewReader("")), 0, nil,
			"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{"Content-Length in Header", "POST", strings.NewReader("abc"), 3, http.Header{"Content-Length": {"99"}},
			"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc"},
		{"chunked in Header with a length", "POST", strings.NewReader("abc"), 3, http.Header{"Transfer-Encoding": {"chunked"}},
			"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc"},
		{"no body", "POST", http.NoBody, 0, http.Header{"Content-Length": {"5"}},
			"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "http://example.com/", nil)
			req.Body = io.NopCloser(tt.body)
			if tt.body == http.NoBody {
				req.Body = http.NoBody
			}
			req.ContentLength = tt.length
			for k, v := range tt.header {
				req.Header[k] = v
			}
			var buf bytes.Buffer
			if err := http1.WriteRequest(&buf, req, nil); err != nil {
				t.Fatal(err)
			}
			if got := buf.String(); got != tt.want {
				t.Fatalf("got %q\nwant %q", got, tt.want)
			}
		})
	}
}

// rawResponse returns the client side of a connection whose server reads
// one request and answers raw.
func rawResponse(t *testing.T, raw string) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
			return
		}
		io.WriteString(server, raw)
	}()
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(10 * time.Second))
	return client
}

// The header limit covers the 1xx responses and the final one together,
// and more than five 1xx responses are refused, as in net/http.
func TestRoundTripHeaderLimits(t *testing.T) {
	early := "HTTP/1.1 103 Early Hints\r\nLink: " + strings.Repeat("l", 400) + "\r\n\r\n"
	final := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	tests := []struct {
		name    string
		raw     string
		limit   int64
		wantErr error // nil: success; errAny: any error
	}{
		{"under", final, 1 << 10, nil},
		{"one header over", "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("a", 2<<10) + "\r\nContent-Length: 2\r\n\r\nok", 1 << 10, http1.ErrHeaderTooLarge},
		{"1xx add up", strings.Repeat(early, 3) + final, 1 << 10, http1.ErrHeaderTooLarge},
		{"1xx under", strings.Repeat(early, 3) + final, 4 << 10, nil},
		{"default under", "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("a", 200<<10) + "\r\nContent-Length: 2\r\n\r\nok", 0, nil},
		{"default over", "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("a", 300<<10) + "\r\nContent-Length: 2\r\n\r\nok", 0, http1.ErrHeaderTooLarge},
		{"five 1xx", strings.Repeat(early, 5) + final, 0, nil},
		{"six 1xx", strings.Repeat(early, 6) + final, 0, errAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := http1.NewConn(rawResponse(t, tt.raw))
			c.MaxHeaderBytes = tt.limit
			req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
			resp, err := c.RoundTrip(req, nil)
			switch {
			case tt.wantErr == nil && err != nil:
				t.Fatal(err)
			case tt.wantErr == nil:
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != http.StatusOK || string(body) != "ok" {
					t.Fatalf("got %d %q", resp.StatusCode, body)
				}
			case err == nil:
				t.Fatal("no error")
			case tt.wantErr != errAny && !errors.Is(err, tt.wantErr):
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			case tt.wantErr == http1.ErrHeaderTooLarge && !strings.Contains(err.Error(), fmt.Sprintf("of %d bytes", cmp.Or(tt.limit, http1.DefaultMaxHeaderBytes))):
				t.Fatalf("err = %v, without the limit", err)
			case tt.wantErr == errAny && errors.Is(err, http1.ErrHeaderTooLarge):
				t.Fatalf("err = %v, want the 1xx count", err)
			}
		})
	}
}

var errAny = errors.New("any error")

// Framings http.ReadResponse refuses and RFC 9112 accepts are read, and the
// connection ends with the response. Conflicting ones stay malformed.
func TestRoundTripFramings(t *testing.T) {
	for _, tt := range []struct {
		name, raw, body string // body "": ErrMalformedResponse
	}{
		{"Content-Length list", "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\nX-A: 1\r\n\r\nhelloEXTRA", "hello"},
		{"Content-Length list and field", "HTTP/1.1 200 OK\r\nContent-Length: 5,5\r\nContent-Length: 5\r\n\r\nhello", "hello"},
		{"Content-Length list conflict", "HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\nhello", ""},
		{"Content-Length list empty", "HTTP/1.1 200 OK\r\nContent-Length: 5, \r\n\r\nhello", ""},
		{"Content-Length list with a sign", "HTTP/1.1 200 OK\r\nContent-Length: +5, +5\r\n\r\nhello", ""},
		{"coding then chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", "hello"},
		{"chunked then an empty element", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked,\r\n\r\n5\r\nhello\r\n0\r\n\r\n", "hello"},
		{"chunked in a second field", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n5\r\nhello\r\n0\r\n\r\n", "hello"},
		{"last coding not chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nContent-Length: 2\r\n\r\nhello until close", "hello until close"},
		{"only a coding", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nhello until close", "hello until close"},
		{"empty Transfer-Encoding", "HTTP/1.1 200 OK\r\nTransfer-Encoding: \r\nContent-Length: 2\r\n\r\nhello until close", "hello until close"},
		{"folded Transfer-Encoding", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip,\r\n chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", ""},
		{"bad status line", "HTTP/1.1 OK\r\nContent-Length: 5, 5\r\n\r\nhello", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := http1.NewConn(rawResponse(t, tt.raw))
			req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
			resp, err := c.RoundTrip(req, nil)
			if tt.body == "" {
				if !errors.Is(err, http1.ErrMalformedResponse) {
					t.Fatalf("err = %v, want ErrMalformedResponse", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil || string(body) != tt.body || strings.Contains(tt.raw, "X-A: 1") && resp.Header.Get("X-A") != "1" {
				t.Fatalf("body %q, %v; header %v", body, err, resp.Header)
			}
			if c.KeepAlive(resp) {
				t.Error("connection kept after a normalized head")
			}
		})
	}
}

// A response cut short by the connection is not malformed: closed, timed
// out or closed on our side while the headers are read.
func TestRoundTripLostNotMalformed(t *testing.T) {
	partial := "HTTP/1.1 200 OK\r\nX-A: 1\r\n"
	for _, tt := range []struct {
		name string
		lose func(c net.Conn)
	}{
		{"closed by the server", nil},
		{"timeout", func(c net.Conn) { c.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) }},
		{"closed here", func(c net.Conn) { time.AfterFunc(100*time.Millisecond, func() { c.Close() }) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { client.Close(); server.Close() })
			go func() {
				if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
					return
				}
				io.WriteString(server, partial)
				if tt.lose == nil {
					server.Close()
				}
			}()
			client.SetDeadline(time.Now().Add(10 * time.Second))
			if tt.lose != nil {
				tt.lose(client)
			}
			req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
			_, err := http1.NewConn(client).RoundTrip(req, nil)
			if err == nil || errors.Is(err, http1.ErrMalformedResponse) {
				t.Fatalf("err = %v, want a read error that is not ErrMalformedResponse", err)
			}
		})
	}
}
