package lab_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

func chromeSpec() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
	return &spec, err
}

func dial(t *testing.T, srv *lab.Server) *utls.UConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := tlsdial.Dial(ctx, "tcp", srv.Addr, tlsdial.Config{
		Spec: chromeSpec,
		TLS:  &utls.Config{ServerName: lab.ServerName, RootCAs: srv.RootCAs},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestOfferedProtocols(t *testing.T) {
	tests := []struct {
		offer []string
		want  string
	}{
		{offer: []string{"h2"}, want: "h2"},
		{offer: []string{"http/1.1"}, want: "http/1.1"},
		{offer: []string{"h2", "http/1.1"}, want: "h2"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.offer, ","), func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: tt.offer})
			conn := dial(t, srv)
			if got := conn.ConnectionState().NegotiatedProtocol; got != tt.want {
				t.Fatalf("client ALPN = %q, want %q", got, tt.want)
			}
			if got := srv.NextConn(t).State.NegotiatedProtocol; got != tt.want {
				t.Fatalf("lab ALPN = %q, want %q", got, tt.want)
			}
		})
	}
}

// The raw ClientHello is usable by utls.Fingerprinter.
func TestClientHelloCapture(t *testing.T) {
	srv := lab.Start(t, lab.Options{})
	dial(t, srv)
	c := srv.NextConn(t)
	if c.HandshakeErr != nil {
		t.Fatal(c.HandshakeErr)
	}
	if len(c.ClientHello) < 4 || c.ClientHello[0] != 1 {
		t.Fatalf("ClientHello does not start with handshake type 1: % x", c.ClientHello[:min(4, len(c.ClientHello))])
	}
	if !bytes.Equal(c.ClientHelloRecord[5:], c.ClientHello) {
		t.Fatal("ClientHelloRecord does not wrap ClientHello")
	}

	spec, err := (&utls.Fingerprinter{}).FingerprintClientHello(c.ClientHelloRecord)
	if err != nil {
		t.Fatal(err)
	}
	var alpn []string
	for _, ext := range spec.Extensions {
		if e, ok := ext.(*utls.ALPNExtension); ok {
			alpn = e.AlpnProtocols
		}
	}
	if !slices.Equal(alpn, []string{"h2", "http/1.1"}) {
		t.Fatalf("fingerprinted ALPN = %q", alpn)
	}
}

func TestH2Capture(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	cc, err := (&http2.Transport{}).NewClientConn(dial(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/path", nil)
	req.Header.Set("X-Lab", "1")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}

	frames, err := srv.NextConn(t).H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) == 0 || frames[0].Type != "SETTINGS" || frames[0].StreamID != 0 || len(frames[0].Settings) == 0 {
		t.Fatalf("first frame = %+v, want the client SETTINGS", frames)
	}

	var headers *lab.H2Frame
	for i := range frames {
		if frames[i].Type == "HEADERS" {
			headers = &frames[i]
			break
		}
	}
	if headers == nil || headers.StreamID != 1 {
		t.Fatalf("no HEADERS frame on stream 1 in %+v", frames)
	}
	names := make([]string, len(headers.Headers))
	values := map[string]string{}
	for i, f := range headers.Headers {
		names[i] = f.Name
		values[f.Name] = f.Value
	}
	// Pseudo-headers come first.
	firstRegular := slices.IndexFunc(names, func(n string) bool { return !strings.HasPrefix(n, ":") })
	if firstRegular < 0 || slices.ContainsFunc(names[firstRegular:], func(n string) bool { return strings.HasPrefix(n, ":") }) {
		t.Errorf("pseudo-headers not first: %q", names)
	}
	if values[":method"] != "GET" || values[":path"] != "/path" || values[":authority"] != "example.com" || values["x-lab"] != "1" {
		t.Errorf("decoded headers = %v", headers.Headers)
	}
}

const rawRequest = "GET /raw HTTP/1.1\r\nHost: example.com\r\nX-Mixed-Case: v\r\nuser-agent: lab\r\n\r\n"

// writeRaw sends rawRequest and reads the response.
func writeRaw(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, rawRequest); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

// HTTP/1.1 requests are kept byte for byte, including the case of names.
func TestH1Capture(t *testing.T) {
	t.Run("TLS", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
		writeRaw(t, dial(t, srv))
		if got := string(srv.NextConn(t).Bytes()); got != rawRequest {
			t.Fatalf("captured %q, want %q", got, rawRequest)
		}
	})
	t.Run("plain", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{Plain: true})
		conn, err := net.Dial("tcp", srv.Addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		writeRaw(t, conn)
		c := srv.NextConn(t)
		if c.ClientHello != nil {
			t.Error("plain connection has a ClientHello")
		}
		if got := string(c.Bytes()); got != rawRequest {
			t.Fatalf("captured %q, want %q", got, rawRequest)
		}
	})
}

// A server with Memory serves the connections of Dial, in a synctest
// bubble, where a sleep takes no time; Dial fails without Memory, after
// Close and with its context done.
func TestMemory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := lab.Start(t, lab.Options{Plain: true, Memory: true})
		if srv.Addr != "memory" {
			t.Errorf("Addr = %q", srv.Addr)
		}
		raw, err := srv.Dial(context.Background(), "tcp", "ignored:80")
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		time.Sleep(time.Hour)
		io.WriteString(raw, "GET / HTTP/1.1\r\nHost: lab\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(raw), nil)
		if err != nil {
			t.Fatal(err)
		}
		if body, _ := io.ReadAll(resp.Body); string(body) != "ok" {
			t.Errorf("body %q", body)
		}
		if got := string(srv.NextConn(t).Bytes()); got != "GET / HTTP/1.1\r\nHost: lab\r\n\r\n" {
			t.Errorf("received %q", got)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		for range 20 { // a select would pick at random
			if c, err := srv.Dial(ctx, "tcp", ""); err != context.Canceled {
				t.Errorf("Dial with a canceled context: %v", err)
				if c != nil {
					c.Close()
				}
			}
		}
		srv.Close()
		if _, err := srv.Dial(context.Background(), "tcp", ""); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Dial after Close: %v", err)
		}
	})
	if _, err := lab.Start(t, lab.Options{}).Dial(context.Background(), "tcp", ""); err == nil {
		t.Error("Dial without Memory")
	}
}
