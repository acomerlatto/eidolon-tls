package dispatch_test

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

var bothProtos = [][]string{{"http/1.1"}, {"h2"}}

// newRequest returns a request bounded to 10 seconds, so a request the
// server never sees the end of fails instead of hanging the package.
func newRequest(t *testing.T, method, url string, body io.Reader) (*http.Request, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return http.NewRequestWithContext(ctx, method, url, body)
}

// received is what a handler saw of a request body.
type received struct {
	length int64
	te     string
	body   string
}

func recorder(got chan<- received) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- received{r.ContentLength, strings.Join(r.TransferEncoding, ","), string(b)}
	})
}

// A body of unknown length is sent by both engines: chunked over
// HTTP/1.1, without content-length over HTTP/2.
func TestUnknownLengthBody(t *testing.T) {
	want := map[string]received{
		"http/1.1": {-1, "chunked", "streamed body"},
		"h2":       {-1, "", "streamed body"},
	}
	for _, protos := range bothProtos {
		t.Run(protos[0], func(t *testing.T) {
			got := make(chan received, 1)
			srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: recorder(got)})
			tr := transport(srv)
			defer tr.Close()
			req, _ := newRequest(t, http.MethodPost, "https://example.com/", io.NopCloser(strings.NewReader("streamed body")))
			req.ContentLength = -1
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if g := <-got; g != want[protos[0]] {
				t.Fatalf("server got %+v, want %+v", g, want[protos[0]])
			}
		})
	}
}

// Content-Length in Header is ignored by both engines: the body decides.
func TestHeaderContentLengthIgnored(t *testing.T) {
	for _, protos := range bothProtos {
		t.Run(protos[0], func(t *testing.T) {
			got := make(chan received, 1)
			srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: recorder(got)})
			tr := transport(srv)
			defer tr.Close()
			req, _ := newRequest(t, http.MethodPost, "https://example.com/", strings.NewReader("abc"))
			req.Header.Set("Content-Length", "99")
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if g := <-got; g != (received{3, "", "abc"}) {
				t.Fatalf("server got %+v", g)
			}
		})
	}
}

// In-memory bodies (bytes, JSON, form) carry their length and GetBody, so
// a 307 sends them again on both engines.
func TestInMemoryBodies(t *testing.T) {
	form := url.Values{"a": {"1"}, "b": {"x y"}}.Encode()
	bodies := map[string]func() io.Reader{
		"bytes.Reader":   func() io.Reader { return bytes.NewReader([]byte("raw bytes")) },
		"bytes.Buffer":   func() io.Reader { return bytes.NewBufferString(`{"json":true}`) },
		"strings.Reader": func() io.Reader { return strings.NewReader(form) },
	}
	for name, body := range bodies {
		for _, protos := range bothProtos {
			t.Run(name+"/"+protos[0], func(t *testing.T) {
				want, _ := io.ReadAll(body())
				got := make(chan received, 2)
				srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := io.ReadAll(r.Body)
					got <- received{r.ContentLength, strings.Join(r.TransferEncoding, ","), string(b)}
					if r.URL.Path == "/from" {
						http.Redirect(w, r, "/next", http.StatusTemporaryRedirect)
					}
				})})
				tr := transport(srv)
				defer tr.Close()
				req, _ := newRequest(t, http.MethodPost, "https://example.com/from", body())
				resp, err := (&http.Client{Transport: tr}).Do(req)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				for hop := range 2 {
					if g := <-got; g != (received{int64(len(want)), "", string(want)}) {
						t.Fatalf("hop %d: server got %+v", hop, g)
					}
				}
			})
		}
	}
}

func encode(coding string, s string) []byte {
	var b bytes.Buffer
	var w io.WriteCloser
	switch coding {
	case "gzip":
		w = gzip.NewWriter(&b)
	case "zlib":
		w = zlib.NewWriter(&b)
	case "raw":
		w, _ = flate.NewWriter(&b, flate.DefaultCompression)
	}
	io.WriteString(w, s)
	w.Close()
	return b.Bytes()
}

// gzip and deflate (zlib or raw) are decoded on both engines; other
// codings, several codings and HEAD come back as they were sent.
func TestDecompression(t *testing.T) {
	text := strings.Repeat("decoded text ", 100)
	tests := []struct {
		name     string
		header   string
		body     []byte
		decoded  bool
		wantBody string
	}{
		{"gzip", "gzip", encode("gzip", text), true, text},
		{"x-gzip", "x-gzip", encode("gzip", text), true, text},
		{"case and space", " GZip ", encode("gzip", text), true, text},
		{"deflate zlib", "deflate", encode("zlib", text), true, text},
		{"deflate raw", "deflate", encode("raw", text), true, text},
		{"br", "br", []byte("brotli bytes"), false, "brotli bytes"},
		{"two codings", "gzip, br", []byte("layered"), false, "layered"},
		{"identity", "", []byte(text), false, text},
	}
	for _, tt := range tests {
		for _, protos := range bothProtos {
			t.Run(tt.name+"/"+protos[0], func(t *testing.T) {
				srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if tt.header != "" {
						w.Header().Set("Content-Encoding", tt.header)
					}
					w.Header().Set("Content-Length", fmt.Sprint(len(tt.body)))
					w.Write(tt.body)
				})})
				tr := transport(srv)
				defer tr.Close()
				req, _ := newRequest(t, http.MethodGet, "https://example.com/", nil)
				resp, err := tr.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != tt.wantBody {
					t.Fatalf("body = %.40q", body)
				}
				ce := resp.Header.Get("Content-Encoding")
				if resp.Uncompressed != tt.decoded || (ce == "") != (tt.decoded || tt.header == "") {
					t.Fatalf("Uncompressed %v, Content-Encoding %q", resp.Uncompressed, ce)
				}
				if tt.decoded && (resp.ContentLength != -1 || resp.Header.Get("Content-Length") != "") {
					t.Fatalf("ContentLength %d, header %q", resp.ContentLength, resp.Header.Get("Content-Length"))
				}
			})
		}
	}
}

// A HEAD response keeps its headers; a malformed body fails on Read, not
// in RoundTrip; DisableDecompression delivers the bytes as sent.
func TestDecompressionEdges(t *testing.T) {
	gz := encode("gzip", "payload")
	for _, protos := range bothProtos {
		t.Run(protos[0], func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: protos, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				if r.URL.Path == "/bad" {
					w.Write([]byte("not gzip at all"))
					return
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(gz)))
				if r.Method != http.MethodHead {
					w.Write(gz)
				}
			})})
			tr := transport(srv)
			defer tr.Close()

			req, _ := newRequest(t, http.MethodHead, "https://example.com/", nil)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.Uncompressed || resp.Header.Get("Content-Encoding") != "gzip" {
				t.Errorf("HEAD: Uncompressed %v, Content-Encoding %q", resp.Uncompressed, resp.Header.Get("Content-Encoding"))
			}

			req, _ = newRequest(t, http.MethodGet, "https://example.com/bad", nil)
			resp, err = tr.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			if _, err := io.ReadAll(resp.Body); err == nil {
				t.Error("malformed gzip read without error")
			}
			resp.Body.Close()

			raw := transport(srv)
			raw.DisableDecompression = true
			defer raw.Close()
			req, _ = newRequest(t, http.MethodGet, "https://example.com/", nil)
			resp, err = raw.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !bytes.Equal(body, gz) || resp.Uncompressed {
				t.Errorf("DisableDecompression: body %q, Uncompressed %v", body, resp.Uncompressed)
			}
		})
	}
}

// A decoded body read to the end releases the HTTP/1.1 connection. In a
// chunked response whose last chunk comes apart, the decoders stop before
// it, and it marks the end of the body.
func TestDecompressionKeepsConnection(t *testing.T) {
	for _, tc := range []struct {
		coding  string
		chunked bool
	}{
		{"gzip", false}, {"zlib", false}, {"raw", false},
		{"gzip", true}, {"zlib", true}, {"raw", true},
	} {
		coding := tc.coding
		name := coding
		if tc.chunked {
			name += "/chunked"
		}
		t.Run(name, func(t *testing.T) {
			payload := encode(coding, "keep me")
			header := "deflate"
			if coding == "gzip" {
				header = "gzip"
			}
			srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", header)
				if !tc.chunked {
					w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
					w.Write(payload)
					return
				}
				// No Content-Length: chunked. The last chunk comes later,
				// alone, as when a server ends the stream after a pause.
				w.Write(payload)
				w.(http.Flusher).Flush()
				time.Sleep(20 * time.Millisecond)
			})})
			tr := transport(srv)
			defer tr.Close()
			for range 2 {
				req, _ := newRequest(t, http.MethodGet, "https://example.com/", nil)
				resp, err := tr.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if string(body) != "keep me" {
					t.Fatalf("body %q", body)
				}
			}
			if n := srv.Accepted(); n != 1 {
				t.Fatalf("%d connections, want 1", n)
			}
		})
	}
}
