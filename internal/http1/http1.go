// Package http1 is the HTTP/1.1 engine. It writes requests with controlled
// header order and name spelling, and reads responses with http.ReadResponse.
//
// A Conn carries one request at a time and keeps its reader between
// requests, so it can be pooled. The pool itself belongs to the caller.
package http1

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// Spelling maps a lowercase header name to the exact spelling sent on the
// wire, as captured from the browser. Names not in the map are sent in
// canonical form (User-Agent).
type Spelling map[string]string

// defaultOrder applies when the context carries no header order: Host first,
// then alphabetical, never the map iteration order.
var defaultOrder = &order.Order{Header: []string{"host"}}

// ErrUpgrade reports a 101 response; Upgrade is outside phase 1.
var ErrUpgrade = errors.New("http1: unexpected 101 Switching Protocols")

// ErrHeaderTooLarge reports response headers, 1xx included, over the limit
// of the connection. The dispatcher reports the HTTP/2 limit with it too.
var ErrHeaderTooLarge = errors.New("eidolon: response headers exceed the limit")

// ErrMalformedResponse reports a response that cannot be read: a bad
// status line or header, conflicting Content-Length values, too many 1xx
// responses. A connection lost while reading is not one.
var ErrMalformedResponse = errors.New("eidolon: malformed HTTP/1.1 response")

// DefaultMaxHeaderBytes bounds the headers of a response, 1xx included,
// as Chrome does (kMaxHeaderBufSize, 256 KiB).
const DefaultMaxHeaderBytes = 256 << 10

// max1xx bounds the informational responses before the final one, as
// net/http does.
const max1xx = 5

// WriteRequest writes req to w as HTTP/1.1. Header order comes from
// order.FromContext(req.Context()); spelling from spell. Nothing is written
// if the request is invalid.
func WriteRequest(w io.Writer, req *http.Request, spell Spelling) error {
	head, err := encodeHead(req, spell)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(w)
	bw.WriteString(head)
	if unknownLength(req) {
		cw := httputil.NewChunkedWriter(bw)
		if _, err := io.Copy(cw, req.Body); err != nil {
			return err
		}
		cw.Close() // the last chunk; no trailers
		bw.WriteString("\r\n")
	} else if req.Body != nil && req.ContentLength > 0 {
		n, err := io.Copy(bw, io.LimitReader(req.Body, req.ContentLength))
		if err != nil {
			return err
		}
		if n != req.ContentLength {
			return fmt.Errorf("http1: body has %d bytes, ContentLength is %d", n, req.ContentLength)
		}
		if extra, _ := io.CopyN(io.Discard, req.Body, 1); extra > 0 {
			return fmt.Errorf("http1: body is longer than ContentLength %d", req.ContentLength)
		}
	}
	return bw.Flush()
}

// unknownLength reports whether req has a body of unknown length, sent
// chunked (RFC 9112 section 7.1), as net/http does; the H2 engine sends it
// without content-length.
func unknownLength(req *http.Request) bool {
	return req.Body != nil && req.Body != http.NoBody && req.ContentLength <= 0
}

// Conn is an HTTP/1.1 connection. Its reader lives as long as the
// connection, so a byte read past one response is never lost.
type Conn struct {
	conn net.Conn
	tap  tap
	br   *bufio.Reader
	sent int64 // bytes written by the last RoundTrip
	// mixed: the last response had both Transfer-Encoding and
	// Content-Length.
	mixed bool
	idle  chan error // the error of the idle watch, when one runs

	// MaxHeaderBytes bounds the bytes read from the connection while the
	// headers of a response, 1xx included, are read. Zero means
	// DefaultMaxHeaderBytes.
	MaxHeaderBytes int64
}

// NewConn returns a Conn over c.
func NewConn(c net.Conn) *Conn {
	hc := &Conn{conn: c, tap: tap{r: c}}
	hc.br = bufio.NewReader(&hc.tap)
	return hc
}

// Close closes the connection.
func (c *Conn) Close() error { return c.conn.Close() }

// Sent returns the bytes the last RoundTrip wrote to the connection. Zero
// means the request never reached the wire and the connection is unchanged.
func (c *Conn) Sent() int64 { return c.sent }

// RoundTrip writes req and reads the final response, skipping 1xx
// informational responses. The response body reads from the connection;
// the next request may start only after the body reached EOF.
func (c *Conn) RoundTrip(req *http.Request, spell Spelling) (*http.Response, error) {
	c.sent = 0
	if err := WriteRequest(writeCounter{c}, req, spell); err != nil {
		return nil, err
	}
	limit := c.MaxHeaderBytes
	if limit <= 0 {
		limit = DefaultMaxHeaderBytes
	}
	// The limit covers the 1xx responses and the final one together, as
	// in net/http; bytes the reader takes ahead count too.
	c.tap.left = limit
	for n1xx := 0; ; {
		// The raw head is recorded because ReadResponse drops
		// Content-Length when the response is chunked.
		c.tap.rec = append(c.tap.rec[:0], peekBuffered(c.br)...)
		c.tap.on = true
		resp, err := http.ReadResponse(c.br, req)
		c.tap.on = false
		if err != nil {
			if c.tap.left <= 0 {
				return nil, fmt.Errorf("%w of %d bytes", ErrHeaderTooLarge, limit)
			}
			if !readFailed(err) {
				err = fmt.Errorf("%w: %w", ErrMalformedResponse, err)
			}
			return nil, err
		}
		switch {
		case resp.StatusCode == http.StatusSwitchingProtocols:
			resp.Body.Close()
			return nil, ErrUpgrade
		case resp.StatusCode >= 100 && resp.StatusCode < 200:
			resp.Body.Close()
			if n1xx++; n1xx > max1xx {
				return nil, fmt.Errorf("%w: more than %d informational responses", ErrMalformedResponse, max1xx)
			}
			continue
		}
		c.mixed = bothFramings(c.tap.rec)
		return resp, nil
	}
}

// KeepAlive reports whether the connection may carry another request once
// the body of resp reached EOF. A response with both Transfer-Encoding and
// Content-Length is read by Transfer-Encoding and ends the connection (RFC
// 9112 section 6.3, specification section 6.3).
func (c *Conn) KeepAlive(resp *http.Response) bool { return !resp.Close && !c.mixed }

// Watch starts watching the idle connection: dead runs if the server sends
// anything or closes it. Reuse stops the watch.
func (c *Conn) Watch(dead func()) {
	c.idle = make(chan error, 1)
	go func() {
		_, err := c.br.Peek(1)
		c.idle <- err
		// Reuse is the only one to set a deadline on an idle connection.
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			dead()
		}
	}()
}

// Reuse stops the idle watch and reports whether the connection can carry
// a new request: the server neither sent anything nor closed it.
func (c *Conn) Reuse() bool {
	if c.idle == nil {
		return true
	}
	c.conn.SetReadDeadline(time.Unix(1, 0)) // in the past: unblocks the peek
	err := <-c.idle
	c.idle = nil
	c.conn.SetReadDeadline(time.Time{})
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// readFailed reports whether err comes from reading the connection, as
// opposed to parsing what was read. ReadResponse reports an early io.EOF
// as io.ErrUnexpectedEOF; io.ErrClosedPipe comes from in-memory
// connections, such as one from a custom dial. Timeouts and net.ErrClosed
// are net.Error values.
func readFailed(err error) bool {
	var ne net.Error
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) ||
		errors.As(err, &ne)
}

// tap records what the reader takes from the connection while on, and
// bounds it to left bytes.
type tap struct {
	r    io.Reader
	on   bool
	rec  []byte
	left int64
}

func (t *tap) Read(p []byte) (int, error) {
	if !t.on {
		return t.r.Read(p)
	}
	if t.left <= 0 {
		return 0, ErrHeaderTooLarge
	}
	if int64(len(p)) > t.left {
		p = p[:t.left]
	}
	n, err := t.r.Read(p)
	t.left -= int64(n)
	t.rec = append(t.rec, p[:n]...)
	return n, err
}

func peekBuffered(br *bufio.Reader) []byte {
	b, _ := br.Peek(br.Buffered())
	return b
}

// bothFramings reports whether the head of a response, as received, has
// both Transfer-Encoding and Content-Length fields.
func bothFramings(raw []byte) bool {
	var te, cl bool
	lines := bytes.Split(raw, []byte("\n"))
	for _, line := range lines[1:] { // after the status line
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			break // end of the head
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // obsolete line folding: not a field name
		}
		name, _, _ := bytes.Cut(line, []byte(":"))
		switch strings.ToLower(string(name)) {
		case "transfer-encoding":
			te = true
		case "content-length":
			cl = true
		}
	}
	return te && cl
}

// writeCounter counts the bytes written to the connection.
type writeCounter struct{ c *Conn }

func (w writeCounter) Write(p []byte) (int, error) {
	n, err := w.c.conn.Write(p)
	w.c.sent += int64(n)
	return n, err
}

// encodeHead returns the request line and the header block.
func encodeHead(req *http.Request, spell Spelling) (string, error) {
	if req.URL == nil {
		return "", errors.New("http1: Request.URL is nil")
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	if !validMethod(method) {
		return "", fmt.Errorf("http1: invalid method %q", method)
	}
	// CONNECT needs authority-form (RFC 9112 section 3.2.3); tunnels,
	// trailers and Upgrade are outside phase 1.
	if method == http.MethodConnect {
		return "", errors.New("http1: CONNECT is not supported")
	}
	if len(req.Trailer) > 0 {
		return "", errors.New("http1: trailers are not supported")
	}
	target := req.URL.RequestURI()
	if !validTarget(target) {
		return "", fmt.Errorf("http1: invalid request target %q", target)
	}
	if exact := order.ExactFromContext(req.Context()); exact != nil {
		return encodeExact(method, target, exact, req)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return "", err
	}
	if host == "" || !httpguts.ValidHostHeader(host) {
		return "", fmt.Errorf("http1: invalid Host %q", host)
	}

	fields := []order.Field{{Name: "host", Value: host}}
	var cookieName string
	var cookies []string
	// Keys in byte order: two keys of one name in different case ("X-A",
	// "x-a") are merged the same way every time.
	for _, name := range slices.Sorted(maps.Keys(req.Header)) {
		values := req.Header[name]
		switch strings.ToLower(name) {
		case "host":
			continue // req.Host and the URL decide Host, as in net/http
		case "content-length":
			// The body decides the framing, as in net/http and the H2
			// engine; exact mode sends a Content-Length as given.
			continue
		case "transfer-encoding":
			// As the H2 engine: "chunked" is left to the body, anything
			// else is refused.
			if len(values) > 1 || len(values) == 1 && values[0] != "" && values[0] != "chunked" {
				return "", fmt.Errorf("http1: unsupported Transfer-Encoding %q", values)
			}
			continue
		case "upgrade":
			return "", errors.New("http1: Upgrade is not supported")
		case "cookie":
			// One Cookie field (RFC 6265 section 5.4), placed by the order
			// like any other name.
			if cookieName == "" {
				cookieName = name
			}
			cookies = append(cookies, values...)
			continue
		case "user-agent":
			// As the H2 engine and net/http: the first value only, and none
			// if it is empty.
			if len(values) == 0 || values[0] == "" {
				continue
			}
			values = values[:1]
		}
		for _, v := range values {
			fields = append(fields, order.Field{Name: name, Value: v})
		}
	}
	if cookies != nil {
		fields = append(fields, order.Field{Name: cookieName, Value: strings.Join(cookies, "; ")})
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	if !hasBody && req.ContentLength > 0 {
		return "", errors.New("http1: ContentLength set without a body")
	}
	switch {
	case unknownLength(req):
		fields = append(fields, order.Field{Name: "transfer-encoding", Value: "chunked"})
	case req.ContentLength > 0:
		fields = append(fields, order.Field{Name: "content-length", Value: strconv.FormatInt(req.ContentLength, 10)})
	case method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch:
		// RFC 9110 section 8.6: the method defines content, so its absence
		// is stated; the H2 engine does the same.
		fields = append(fields, order.Field{Name: "content-length", Value: "0"})
	}

	o := order.FromContext(req.Context())
	if o == nil || o.Header == nil {
		o = defaultOrder
	}
	var b strings.Builder
	b.WriteString(method + " " + target + " HTTP/1.1\r\n")
	for _, f := range o.Sort(fields) {
		name, err := spelled(f.Name, spell)
		if err != nil {
			return "", err
		}
		if !validValue(f) {
			return "", fmt.Errorf("http1: invalid value for header %s", name)
		}
		b.WriteString(name + ": " + f.Value + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String(), nil
}

// encodeExact returns the head of a request in exact mode: the fields as
// given, names spelled as given and nothing added. Host is required, and
// the framing must match the body; nothing is corrected.
func encodeExact(method, target string, exact []order.Field, req *http.Request) (string, error) {
	hasBody := req.Body != nil && req.Body != http.NoBody
	if hasBody && req.ContentLength <= 0 {
		return "", errors.New("http1: body without a known ContentLength")
	}
	if !hasBody && req.ContentLength > 0 {
		return "", errors.New("http1: ContentLength set without a body")
	}
	var hosts, lengths int
	var b strings.Builder
	b.WriteString(method + " " + target + " HTTP/1.1\r\n")
	for _, f := range exact {
		if !httpguts.ValidHeaderFieldName(f.Name) {
			return "", fmt.Errorf("http1: invalid header name %q", f.Name)
		}
		if !validValue(f) {
			return "", fmt.Errorf("http1: invalid value for header %s", f.Name)
		}
		switch strings.ToLower(f.Name) {
		case "host":
			hosts++
			if !httpguts.ValidHostHeader(f.Value) {
				return "", fmt.Errorf("http1: invalid Host %q", f.Value)
			}
		case "content-length":
			lengths++
			if n, err := strconv.ParseInt(f.Value, 10, 64); err != nil || n != req.ContentLength {
				return "", fmt.Errorf("http1: exact Content-Length %q does not match the body of %d bytes", f.Value, req.ContentLength)
			}
		case "transfer-encoding":
			return "", errors.New("http1: Transfer-Encoding is not supported; the body is sent with Content-Length")
		case "upgrade":
			return "", errors.New("http1: Upgrade is not supported")
		}
		b.WriteString(f.Name + ": " + f.Value + "\r\n")
	}
	switch {
	case hosts != 1:
		return "", fmt.Errorf("http1: exact headers need one Host field, have %d", hosts)
	case lengths > 1:
		return "", errors.New("http1: exact headers repeat Content-Length")
	case hasBody && lengths == 0:
		return "", errors.New("http1: exact headers need a Content-Length field for the body")
	}
	b.WriteString("\r\n")
	return b.String(), nil
}

// validValue reports whether a field value can be sent: valid characters
// and no leading or trailing whitespace, as in the H2 engine. Cookie is
// exempt from the whitespace rule there because it is split into crumbs.
func validValue(f order.Field) bool {
	return httpguts.ValidHeaderFieldValue(f.Value) &&
		(f.Value == strings.Trim(f.Value, " \t") || strings.EqualFold(f.Name, "cookie"))
}

// spelled returns the wire spelling of name.
func spelled(name string, spell Spelling) (string, error) {
	if !httpguts.ValidHeaderFieldName(name) {
		return "", fmt.Errorf("http1: invalid header name %q", name)
	}
	s, ok := spell[strings.ToLower(name)]
	if !ok {
		return textproto.CanonicalMIMEHeaderKey(name), nil
	}
	if !strings.EqualFold(s, name) || !httpguts.ValidHeaderFieldName(s) {
		return "", fmt.Errorf("http1: spelling %q does not match header %q", s, name)
	}
	return s, nil
}

func validMethod(m string) bool {
	return m != "" && strings.IndexFunc(m, func(r rune) bool { return !httpguts.IsTokenRune(r) }) < 0
}

// validTarget accepts origin-form made of visible ASCII only: the URL is
// percent-encoded before the engine, and raw bytes are never sent.
func validTarget(t string) bool {
	if !strings.HasPrefix(t, "/") {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] <= ' ' || t[i] >= 0x7f {
			return false
		}
	}
	return true
}
