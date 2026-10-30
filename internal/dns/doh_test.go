package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// roundTripFunc is an http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestParseTemplate(t *testing.T) {
	for _, tt := range []struct {
		template, host, get, post string
	}{
		{"https://dns.test/dns-query{?dns}", "dns.test", "https://dns.test/dns-query?dns=Q", ""},
		{"https://dns.test:8443/q?ct=1{&dns}", "dns.test", "https://dns.test:8443/q?ct=1&dns=Q", ""},
		{"https://dns.test/q/{dns}/x", "dns.test", "https://dns.test/q/Q/x", ""},
		{"https://10.0.0.1/dns-query", "10.0.0.1", "", "https://10.0.0.1/dns-query"},
		{"https://[::1]/dns-query{?dns}", "::1", "https://[::1]/dns-query?dns=Q", ""},
	} {
		tp, err := ParseTemplate(tt.template)
		if err != nil {
			t.Errorf("%s: %v", tt.template, err)
			continue
		}
		if tp.Host != tt.host || tp.post != (tt.post != "") {
			t.Errorf("%s: host %q, post %v", tt.template, tp.Host, tp.post)
		}
		if tt.post == "" && tp.expand("Q") != tt.get {
			t.Errorf("%s: GET %q, want %q", tt.template, tp.expand("Q"), tt.get)
		}
		if tt.post != "" && tp.expand("") != tt.post {
			t.Errorf("%s: POST %q, want %q", tt.template, tp.expand(""), tt.post)
		}
	}
	for _, s := range []string{
		"http://dns.test/dns-query{?dns}",
		"https:///dns-query{?dns}",
		"https://user:pw@dns.test/dns-query",
		"https://dns.test/dns-query#x",
		"https://dns.test/dns-query{?name}",
		"https://dns.test/dns-query{?dns,ct}",
		"https://dns.test/dns-query{/dns}",
		"https://dns.test/dns-query{?dns",
		"https://dns.test/{dns}{?dns}",
		"https://dns.test/}{?dns}",
		"https://dns.test/%zz{?dns}",
		"dns.test/dns-query",
	} {
		if _, err := ParseTemplate(s); err == nil {
			t.Errorf("%s: accepted", s)
		}
	}
}

// dohServer answers a DoH request with status, contentType and body.
// It records the requests and the bodies of the responses.
func dohServer(status int, contentType string, length int64, body []byte, got *[]*http.Request, bodies *[]*closeBody) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		*got = append(*got, r)
		h := http.Header{}
		if contentType != "" {
			h.Set("Content-Type", contentType)
		}
		b := &closeBody{Reader: bytes.NewReader(body)}
		*bodies = append(*bodies, b)
		return &http.Response{StatusCode: status, Header: h, ContentLength: length, Body: b}, nil
	})
}

// closeBody records its Close.
type closeBody struct {
	io.Reader
	closed bool
}

func (b *closeBody) Close() error { b.closed = true; return nil }

// GET carries the padded query of ID 0 in the dns parameter, POST in its
// body, with Chrome's headers in Chrome's order.
func TestDoHRequest(t *testing.T) {
	want, err := Query(0, "example.com", TypeHTTPS, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, template := range []string{"https://dns.test/dns-query{?dns}", "https://dns.test/dns-query"} {
		var reqs []*http.Request
		tp, err := ParseTemplate(template)
		if err != nil {
			t.Fatal(err)
		}
		d := &DoH{URL: tp, Transport: dohServer(200, "application/dns-message", -1, []byte("answer"), &reqs, new([]*closeBody))}
		ctx := context.WithValue(context.Background(), struct{}{}, 1)
		q, resp, err := d.Exchange(ctx, "example.com", TypeHTTPS)
		if err != nil || !bytes.Equal(q, want) || string(resp) != "answer" {
			t.Fatalf("%s: %x %q %v", template, q, resp, err)
		}
		r := reqs[0]
		if r.Context() != ctx {
			t.Errorf("%s: not the context of Exchange", template)
		}
		header := http.Header{
			"Accept":          {"application/dns-message"},
			"Accept-Language": {"*"},
			"User-Agent":      {"Chrome"},
			"Accept-Encoding": {"identity"},
			order.HeaderKey:   {"host", "connection", "content-length", "accept", "accept-language", "user-agent", "accept-encoding", "content-type", "priority"},
		}
		if strings.HasSuffix(template, "{?dns}") {
			if r.Method != http.MethodGet || r.URL.String() != "https://dns.test/dns-query?dns="+base64.RawURLEncoding.EncodeToString(want) || r.Body != nil {
				t.Errorf("GET %s %v", r.URL, r.Body)
			}
		} else {
			header.Set("Content-Type", "application/dns-message")
			body, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodPost || r.URL.String() != template || !bytes.Equal(body, want) {
				t.Errorf("POST %s %x", r.URL, body)
			}
		}
		if !reflect.DeepEqual(r.Header, header) {
			t.Errorf("%s: header %v", template, r.Header)
		}
	}
}

// Only a 200 of type application/dns-message up to 65535 bytes is an
// answer, as in Chrome.
func TestDoHResponse(t *testing.T) {
	tp, _ := ParseTemplate("https://dns.test/dns-query{?dns}")
	max := bytes.Repeat([]byte{1}, 65535)
	for _, tt := range []struct {
		name        string
		status      int
		contentType string
		length      int64
		body        []byte
		ok          bool
	}{
		{"parameters", 200, "Application/DNS-Message; charset=x", 6, []byte("answer"), true},
		{"65535 bytes", 200, "application/dns-message", -1, max, true},
		{"declared 65535", 200, "application/dns-message", 65535, max, true},
		{"404", 404, "application/dns-message", -1, nil, false},
		{"204", 204, "application/dns-message", -1, nil, false},
		{"text", 200, "text/plain", -1, nil, false},
		{"no type", 200, "", -1, nil, false},
		{"bad type", 200, "application/", -1, nil, false},
		{"declared 65536", 200, "application/dns-message", 65536, nil, false},
		{"65536 bytes", 200, "application/dns-message", -1, append(max, 1), false},
	} {
		var reqs []*http.Request
		var bodies []*closeBody
		d := &DoH{URL: tp, Transport: dohServer(tt.status, tt.contentType, tt.length, tt.body, &reqs, &bodies)}
		_, resp, err := d.Exchange(context.Background(), "example.com", TypeHTTPS)
		if (err == nil) != tt.ok || (tt.ok && !bytes.Equal(resp, tt.body)) {
			t.Errorf("%s: %d bytes, %v", tt.name, len(resp), err)
		}
		if !bodies[0].closed {
			t.Errorf("%s: body not closed", tt.name)
		}
	}
	failing := errors.New("no route")
	d := &DoH{URL: tp, Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, failing })}
	if _, _, err := d.Exchange(context.Background(), "example.com", TypeHTTPS); !errors.Is(err, failing) {
		t.Errorf("transport error: %v", err)
	}
	broken := errors.New("reset")
	d.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/dns-message"}}, ContentLength: -1,
			Body: io.NopCloser(io.MultiReader(strings.NewReader("ab"), errReader{broken}))}, nil
	})
	if _, _, err := d.Exchange(context.Background(), "example.com", TypeHTTPS); !errors.Is(err, broken) {
		t.Errorf("body error: %v", err)
	}
	if _, _, err := d.Exchange(context.Background(), "example.com.", TypeHTTPS); err == nil {
		t.Error("invalid name: no error")
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
