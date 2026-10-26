// Package http1 is the HTTP/1.1 engine. It writes requests with controlled
// header order and name spelling, and reads responses with http.ReadResponse.
//
// This is the M0 skeleton: one request per call on a connection the caller
// owns. Pooling, keep-alive reuse and the framing checks of section 6.3 of
// the specification come in M1.
package http1

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

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
	if req.Body != nil && req.ContentLength > 0 {
		n, err := io.Copy(bw, io.LimitReader(req.Body, req.ContentLength))
		if err != nil {
			return err
		}
		if n != req.ContentLength {
			return fmt.Errorf("http1: body has %d bytes, ContentLength is %d", n, req.ContentLength)
		}
	}
	return bw.Flush()
}

// RoundTrip writes req on rw and reads the final response, skipping 1xx
// informational responses. The response body reads from rw.
func RoundTrip(rw io.ReadWriter, req *http.Request, spell Spelling) (*http.Response, error) {
	if err := WriteRequest(rw, req, spell); err != nil {
		return nil, err
	}
	br := bufio.NewReader(rw)
	for {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		switch {
		case resp.StatusCode == http.StatusSwitchingProtocols:
			resp.Body.Close()
			return nil, ErrUpgrade
		case resp.StatusCode >= 100 && resp.StatusCode < 200:
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
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
	target := req.URL.RequestURI()
	if !validTarget(target) {
		return "", fmt.Errorf("http1: invalid request target %q", target)
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
	for name, values := range req.Header {
		switch strings.ToLower(name) {
		case "host":
			continue // req.Host and the URL decide Host, as in net/http
		case "content-length", "transfer-encoding":
			return "", fmt.Errorf("http1: %s is set from the body, not from Header", name)
		}
		for _, v := range values {
			fields = append(fields, order.Field{Name: name, Value: v})
		}
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	if hasBody && req.ContentLength <= 0 {
		return "", errors.New("http1: body without a known ContentLength")
	}
	if !hasBody && req.ContentLength > 0 {
		return "", errors.New("http1: ContentLength set without a body")
	}
	if req.ContentLength > 0 {
		fields = append(fields, order.Field{Name: "content-length", Value: strconv.FormatInt(req.ContentLength, 10)})
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
		if !httpguts.ValidHeaderFieldValue(f.Value) {
			return "", fmt.Errorf("http1: invalid value for header %s", name)
		}
		b.WriteString(name + ": " + f.Value + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String(), nil
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

func validTarget(t string) bool {
	return strings.HasPrefix(t, "/") && !strings.ContainsAny(t, " \t\r\n")
}
