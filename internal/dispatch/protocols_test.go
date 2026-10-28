package dispatch_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/http2/hpack"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// helloALPN returns the ALPN protocols of the ClientHello the lab received,
// read from the bytes on the wire, and whether it had ALPS.
func helloALPN(t *testing.T, c *lab.Conn) (alpn []string, alps bool) {
	t.Helper()
	spec, err := (&utls.Fingerprinter{}).FingerprintClientHello(c.ClientHelloRecord)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			alpn = e.AlpnProtocols
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			alps = true
		}
	}
	return alpn, alps
}

// do sends a request and returns the response with its body read. A
// request that would hang fails after 10 seconds.
func do(t *testing.T, tr http.RoundTripper, method, url string, body string) (*http.Response, string, error) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, method, url, r)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, string(b), err
}

// Without a restriction the spec is sent as it is: ALPN and ALPS of the
// profile.
func TestProtocolsDefaultKeepsSpec(t *testing.T) {
	srv := lab.Start(t, lab.Options{})
	tr := transport(srv)
	defer tr.Close()
	fetch(t, tr, "https://example.com/")
	alpn, alps := helloALPN(t, srv.NextConn(t))
	if !slices.Equal(alpn, []string{"h2", "http/1.1"}) || !alps {
		t.Fatalf("ALPN %v, ALPS %v; want the spec's", alpn, alps)
	}
}

// HTTP/1.1 only: the ClientHello offers only http/1.1 and no ALPS, so a
// server that prefers h2 answers over HTTP/1.1.
func TestProtocolsHTTP1Only(t *testing.T) {
	srv := lab.Start(t, lab.Options{})
	tr := transport(srv)
	tr.Protocols = []string{tlsdial.ProtoHTTP1}
	defer tr.Close()
	for range 2 {
		resp, _, err := do(t, tr, http.MethodGet, "https://example.com/", "")
		if err != nil {
			t.Fatal(err)
		}
		if resp.ProtoMajor != 1 {
			t.Fatalf("answered over %s", resp.Proto)
		}
	}
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
	alpn, alps := helloALPN(t, srv.NextConn(t))
	if !slices.Equal(alpn, []string{"http/1.1"}) || alps {
		t.Fatalf("ALPN %v, ALPS %v; want [http/1.1] without ALPS", alpn, alps)
	}
}

// HTTP/2 only: a server without ALPN, served by HTTP/1.1, fails with
// ErrProtocolPolicy before any HTTP byte; a server with no common protocol
// fails the handshake. http:// fails without dialing.
func TestProtocolsH2Only(t *testing.T) {
	t.Run("no ALPN", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{}})
		tr := transport(srv)
		tr.Protocols = []string{tlsdial.ProtoH2}
		defer tr.Close()
		if _, _, err := do(t, tr, http.MethodGet, "https://example.com/", ""); !errors.Is(err, dispatch.ErrProtocolPolicy) {
			t.Fatalf("err = %v, want ErrProtocolPolicy", err)
		}
		c := srv.NextConn(t)
		if alpn, alps := helloALPN(t, c); !slices.Equal(alpn, []string{"h2"}) || !alps {
			t.Fatalf("ALPN %v, ALPS %v; want [h2] with ALPS", alpn, alps)
		}
		<-c.Done()
		if b := c.Bytes(); len(b) != 0 {
			t.Fatalf("sent %q", b)
		}
	})
	t.Run("no common protocol", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
		tr := transport(srv)
		tr.Protocols = []string{tlsdial.ProtoH2}
		defer tr.Close()
		if _, _, err := do(t, tr, http.MethodGet, "https://example.com/", ""); err == nil {
			t.Fatal("no error")
		}
		if c := srv.NextConn(t); c.HandshakeErr == nil {
			t.Fatal("handshake completed")
		}
	})
	t.Run("http scheme", func(t *testing.T) {
		var dials atomic.Int32
		tr := &dispatch.Transport{
			Spec:      chromeSpec,
			Protocols: []string{tlsdial.ProtoH2},
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("dialed")
			},
		}
		if _, _, err := do(t, tr, http.MethodGet, "http://example.com/", ""); !errors.Is(err, dispatch.ErrProtocolPolicy) {
			t.Fatalf("err = %v, want ErrProtocolPolicy", err)
		}
		if n := dials.Load(); n != 0 {
			t.Fatalf("%d dials", n)
		}
	})
}

// rawH2 serves h2 connections with raw frames: answer handles the n-th
// request of the connection and returns false to stop serving.
func rawH2(answer func(fr *http2.Framer, stream uint32, n int) bool) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		if _, err := io.ReadFull(c, make([]byte, len(http2.ClientPreface))); err != nil {
			return
		}
		fr := http2.NewFramer(c, c)
		fr.WriteSettings()
		n := 0
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					fr.WriteSettingsAck()
				}
			case *http2.HeadersFrame:
				n++
				if !answer(fr, f.StreamID, n) {
					io.Copy(io.Discard, c) // until the client closes
					return
				}
			}
		}
	}
}

// writeOK answers stream with 200 and body "h2".
func writeOK(fr *http2.Framer, stream uint32) {
	var block bytes.Buffer
	hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: block.Bytes(), EndHeaders: true})
	fr.WriteData(stream, true, []byte("h2"))
}

// HTTP_1_1_REQUIRED, in RST_STREAM or in GOAWAY: the request goes again
// over HTTP/1.1, whatever its method, on a connection that offers only
// http/1.1, and the origin stays on HTTP/1.1.
func TestHTTP11Required(t *testing.T) {
	tests := []struct {
		name   string
		warm   bool // a first request is answered over h2
		refuse func(fr *http2.Framer, stream uint32)
	}{
		{"RST_STREAM", false, func(fr *http2.Framer, stream uint32) {
			fr.WriteRSTStream(stream, http2.ErrCodeHTTP11Required)
		}},
		{"GOAWAY on the first stream", false, func(fr *http2.Framer, stream uint32) {
			fr.WriteGoAway(0, http2.ErrCodeHTTP11Required, nil)
		}},
		// The stream was not processed (above LastStreamID): without
		// patch 0007 the engine retried it on another HTTP/2 connection.
		{"GOAWAY on a later stream", true, func(fr *http2.Framer, stream uint32) {
			fr.WriteGoAway(stream-2, http2.ErrCodeHTTP11Required, nil)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := io.ReadAll(r.Body)
					io.WriteString(w, "h1:"+r.Method+":"+string(b))
				}),
				H2Conn: rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
					if tt.warm && n == 1 {
						writeOK(fr, stream)
						return true
					}
					tt.refuse(fr, stream)
					return false
				}),
			})
			tr := transport(srv)
			defer tr.Close()
			if tt.warm {
				if _, got, err := do(t, tr, http.MethodGet, "https://example.com/", ""); err != nil || got != "h2" {
					t.Fatalf("warm request: %q, %v", got, err)
				}
			}
			resp, got, err := do(t, tr, http.MethodPost, "https://example.com/", "payload")
			if err != nil {
				t.Fatal(err)
			}
			if resp.ProtoMajor != 1 || got != "h1:POST:payload" {
				t.Fatalf("%s %q", resp.Proto, got)
			}
			if _, got, err := do(t, tr, http.MethodGet, "https://example.com/", ""); err != nil || got != "h1:GET:" {
				t.Fatalf("next request: %q, %v", got, err)
			}
			if n := srv.Accepted(); n != 2 {
				t.Fatalf("%d connections, want 2", n)
			}
			srv.NextConn(t)
			if alpn, alps := helloALPN(t, srv.NextConn(t)); !slices.Equal(alpn, []string{"http/1.1"}) || alps {
				t.Fatalf("ALPN %v, ALPS %v; want [http/1.1] without ALPS", alpn, alps)
			}
		})
	}
}

// HTTP_1_1_REQUIRED ends the connection with every stream, as Chrome
// drains the session: a stream the GOAWAY covers is not left to finish,
// and a reset of one stream takes the others too. Each request goes
// again over HTTP/1.1, whatever its method; an answer the server writes
// over h2 afterwards is not read.
func TestHTTP11RequiredDrainsConnection(t *testing.T) {
	h1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		io.WriteString(w, "h1:"+r.Method+":"+string(b))
	})
	t.Run("GOAWAY covering the stream", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{Handler: h1, H2Conn: rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
			fr.WriteGoAway(stream, http2.ErrCodeHTTP11Required, nil)
			writeOK(fr, stream)
			return false
		})})
		tr := transport(srv)
		defer tr.Close()
		resp, got, err := do(t, tr, http.MethodPost, "https://example.com/", "payload")
		if err != nil {
			t.Fatal(err)
		}
		if resp.ProtoMajor != 1 || got != "h1:POST:payload" {
			t.Fatalf("%s %q", resp.Proto, got)
		}
	})
	t.Run("RST_STREAM of another stream", func(t *testing.T) {
		first := make(chan uint32, 1)
		srv := lab.Start(t, lab.Options{Handler: h1, H2Conn: rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
			if n == 1 {
				first <- stream
				return true
			}
			fr.WriteRSTStream(stream, http2.ErrCodeHTTP11Required)
			writeOK(fr, <-first)
			return false
		})})
		tr := transport(srv)
		defer tr.Close()
		type result struct {
			proto string
			got   string
			err   error
		}
		done := make(chan result, 1)
		go func() {
			resp, got, err := do(t, tr, http.MethodGet, "https://example.com/a", "")
			r := result{got: got, err: err}
			if resp != nil {
				r.proto = resp.Proto
			}
			done <- r
		}()
		s := <-first
		first <- s // for the second HEADERS
		resp, got, err := do(t, tr, http.MethodPost, "https://example.com/b", "payload")
		if err != nil {
			t.Fatal(err)
		}
		if resp.ProtoMajor != 1 || got != "h1:POST:payload" {
			t.Fatalf("POST: %s %q", resp.Proto, got)
		}
		r := <-done
		if r.err != nil || r.proto != "HTTP/1.1" || r.got != "h1:GET:" {
			t.Fatalf("GET in flight: %s %q %v", r.proto, r.got, r.err)
		}
	})
}

// With HTTP/2 only, HTTP_1_1_REQUIRED is a policy error.
func TestHTTP11RequiredH2Only(t *testing.T) {
	srv := lab.Start(t, lab.Options{H2Conn: rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
		fr.WriteRSTStream(stream, http2.ErrCodeHTTP11Required)
		return false
	})})
	tr := transport(srv)
	tr.Protocols = []string{tlsdial.ProtoH2}
	defer tr.Close()
	if _, _, err := do(t, tr, http.MethodGet, "https://example.com/", ""); !errors.Is(err, dispatch.ErrProtocolPolicy) {
		t.Fatalf("err = %v, want ErrProtocolPolicy", err)
	}
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
}

// Alt-Svc announcing h3 changes nothing: HTTP/3 is never used.
func TestAltSvcH3Ignored(t *testing.T) {
	srv := lab.Start(t, lab.Options{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		io.WriteString(w, "ok")
	})})
	tr := transport(srv)
	defer tr.Close()
	for range 2 {
		resp, _, err := do(t, tr, http.MethodGet, "https://example.com/", "")
		if err != nil {
			t.Fatal(err)
		}
		if resp.ProtoMajor != 2 {
			t.Fatalf("answered over %s", resp.Proto)
		}
	}
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
}
