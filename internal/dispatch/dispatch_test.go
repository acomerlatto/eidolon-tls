package dispatch_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

func chromeSpec() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
	return &spec, err
}

// transport sends every connection to the lab, whatever the URL host.
func transport(srv *lab.Server) *dispatch.Transport {
	return &dispatch.Transport{
		Spec: chromeSpec,
		TLS:  &utls.Config{RootCAs: srv.RootCAs},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Addr)
		},
		Spelling: map[string]string{"sec-ch-ua": "sec-ch-ua"},
	}
}

var headerOrder = []string{"host", "sec-ch-ua", "user-agent", "accept", "x-a"}

// get sends the same request whatever the protocol.
func get(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(order.WithOrder(ctx, order.Order{Header: headerOrder}), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-A", "a")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "eidolon-test")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="155"`)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("got %s %q", resp.Status, body)
	}
	return resp
}

// h1Names returns the header names of a raw HTTP/1.1 request, as spelled.
func h1Names(t *testing.T, raw []byte) []string {
	t.Helper()
	var names []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Scan() // request line
	for sc.Scan() && sc.Text() != "" {
		name, _, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			t.Fatalf("bad header line %q", sc.Text())
		}
		names = append(names, name)
	}
	return names
}

// h2Names returns the regular header names of the first HEADERS frame.
func h2Names(t *testing.T, c *lab.Conn) []string {
	t.Helper()
	frames, err := c.H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if f.Type != "HEADERS" {
			continue
		}
		var names []string
		for _, h := range f.Headers {
			if !strings.HasPrefix(h.Name, ":") {
				names = append(names, h.Name)
			}
		}
		return names
	}
	t.Fatal("no HEADERS frame")
	return nil
}

// M0 acceptance: one call, dispatched by ALPN to the H2 or the H1 engine,
// with a verifiable Response.TLS and the header order seen by the server.
func TestDispatchByALPN(t *testing.T) {
	tests := []struct {
		name  string
		offer []string
		proto string
	}{
		{name: "h2 only", offer: []string{"h2"}, proto: "h2"},
		{name: "http/1.1 only", offer: []string{"http/1.1"}, proto: "http/1.1"},
		{name: "both", offer: []string{"h2", "http/1.1"}, proto: "h2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: tt.offer})
			resp := get(t, &http.Client{Transport: transport(srv)}, "https://example.com/x")

			wantMajor := 1
			if tt.proto == "h2" {
				wantMajor = 2
			}
			if resp.ProtoMajor != wantMajor {
				t.Errorf("Proto = %s, want major %d", resp.Proto, wantMajor)
			}
			c := srv.NextConn(t)
			st := resp.TLS
			if st == nil {
				t.Fatal("Response.TLS is nil")
			}
			if st.NegotiatedProtocol != tt.proto || st.Version != c.State.Version || st.CipherSuite != c.State.CipherSuite {
				t.Errorf("Response.TLS = %s %#x %#x, server %s %#x %#x",
					st.NegotiatedProtocol, st.Version, st.CipherSuite,
					c.State.NegotiatedProtocol, c.State.Version, c.State.CipherSuite)
			}
			if st.ServerName != lab.ServerName || len(st.VerifiedChains) == 0 || len(st.PeerCertificates) == 0 {
				t.Errorf("Response.TLS ServerName %q, %d chains, %d certificates", st.ServerName, len(st.VerifiedChains), len(st.PeerCertificates))
			}

			// The H2 engine adds accept-encoding (implicit defaults are M1);
			// unlisted names follow in alphabetical order.
			var got, want []string
			if tt.proto == "h2" {
				got = h2Names(t, c)
				want = []string{"sec-ch-ua", "user-agent", "accept", "x-a", "accept-encoding"}
			} else {
				got = h1Names(t, c.Bytes())
				want = []string{"Host", "sec-ch-ua", "User-Agent", "Accept", "X-A"}
			}
			if !slices.Equal(got, want) {
				t.Errorf("header order on the wire = %q, want %q", got, want)
			}
		})
	}
}

func TestDispatchPlainHTTP(t *testing.T) {
	srv := lab.Start(t, lab.Options{Plain: true})
	resp := get(t, &http.Client{Transport: transport(srv)}, "http://example.com/x")
	if resp.ProtoMajor != 1 || resp.TLS != nil {
		t.Errorf("Proto %s, TLS %v; want HTTP/1.1 without TLS", resp.Proto, resp.TLS)
	}
	want := []string{"Host", "sec-ch-ua", "User-Agent", "Accept", "X-A"}
	if got := h1Names(t, srv.NextConn(t).Bytes()); !slices.Equal(got, want) {
		t.Errorf("header order on the wire = %q, want %q", got, want)
	}
}

// A failed handshake sends no HTTP byte.
func TestDispatchTLSFailureSendsNothing(t *testing.T) {
	srv := lab.Start(t, lab.Options{})
	tr := transport(srv)
	tr.TLS = &utls.Config{} // system roots do not trust the lab
	_, err := (&http.Client{Transport: tr}).Get("https://example.com/x")
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want an unknown authority error", err)
	}
	if c := srv.NextConn(t); len(c.Bytes()) != 0 {
		t.Fatalf("server received %q after a failed handshake", c.Bytes())
	}
}

func TestDispatchUnsupportedScheme(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "ftp://example.com/", nil)
	if _, err := (&dispatch.Transport{}).RoundTrip(req); err == nil {
		t.Fatal("no error for ftp://")
	}
}

// Without a pool, each request opens its own connection and closing the
// body closes it: two requests give two lab connections, each with one
// request.
func TestDispatchOneConnectionPerRequest(t *testing.T) {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
	client := &http.Client{Transport: transport(srv)}
	get(t, client, "https://example.com/1")
	get(t, client, "https://example.com/2")
	for _, path := range []string{"/1", "/2"} {
		raw := string(srv.NextConn(t).Bytes())
		if strings.Count(raw, " HTTP/1.1\r\n") != 1 || !strings.HasPrefix(raw, "GET "+path+" ") {
			t.Errorf("connection for %s carried %q", path, raw)
		}
	}
}

// hostSent returns Host (HTTP/1.1) or :authority (HTTP/2) as received.
func hostSent(t *testing.T, c *lab.Conn) string {
	t.Helper()
	if c.State.NegotiatedProtocol != "h2" {
		for _, line := range strings.Split(string(c.Bytes()), "\r\n") {
			if v, ok := strings.CutPrefix(line, "Host: "); ok {
				return v
			}
		}
		t.Fatal("no Host line")
	}
	frames, err := c.H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		for _, h := range f.Headers {
			if h.Name == ":authority" {
				return h.Value
			}
		}
	}
	t.Fatal("no :authority")
	return ""
}

// The destination is normalized once: SNI, verification and Host or
// :authority agree, in both protocols.
func TestDispatchTargetIdentity(t *testing.T) {
	tests := []struct {
		name, url, host string
		wantSNI         string
		wantHost        string
	}{
		{name: "case and default port", url: "https://EXAMPLE.com:443/x", wantSNI: "example.com", wantHost: "example.com"},
		{name: "explicit port", url: "https://example.com:8443/x", wantSNI: "example.com", wantHost: "example.com:8443"},
		// No SNI for an IP address; the certificate is verified against its IP SAN.
		{name: "IP address", url: "https://127.0.0.1:8443/x", wantSNI: "", wantHost: "127.0.0.1:8443"},
		// req.Host changes the header only; the URL decides SNI.
		{name: "Host override", url: "https://example.com/x", host: "other.example", wantSNI: "example.com", wantHost: "other.example"},
	}
	for _, proto := range []string{"h2", "http/1.1"} {
		for _, tt := range tests {
			t.Run(proto+"/"+tt.name, func(t *testing.T) {
				srv := lab.Start(t, lab.Options{NextProtos: []string{proto}})
				req, _ := http.NewRequest(http.MethodGet, tt.url, nil)
				req.Host = tt.host
				resp, err := transport(srv).RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.Request != req || req.Host != tt.host {
					t.Errorf("caller's request changed: Response.Request is original %v, Host %q", resp.Request == req, req.Host)
				}
				c := srv.NextConn(t)
				if c.State.ServerName != tt.wantSNI {
					t.Errorf("SNI = %q, want %q", c.State.ServerName, tt.wantSNI)
				}
				if got := hostSent(t, c); got != tt.wantHost {
					t.Errorf("Host/:authority = %q, want %q", got, tt.wantHost)
				}
			})
		}
	}
}

// Closing the body before the end discards the connection at once; it does
// not wait for the server to finish the body (section 6.3).
func TestDispatchEarlyBodyCloseDoesNotDrain(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			srv := lab.Start(t, lab.Options{
				NextProtos: []string{proto},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, "partial")
					w.(http.Flusher).Flush()
					select { // a body that does not end
					case <-release:
					case <-r.Context().Done():
					}
				}),
			})
			req, _ := http.NewRequest(http.MethodGet, "https://example.com/slow", nil)
			resp, err := transport(srv).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			closed := make(chan error, 1)
			go func() { closed <- resp.Body.Close() }()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("Body.Close waited for the rest of the body")
			}
		})
	}
}

// A dial that ends after Close closes its connection and fails with
// ErrClosed, so no connection escapes the shutdown.
func TestDispatchDialAfterClose(t *testing.T) {
	srv := lab.Start(t, lab.Options{})
	dialing := make(chan struct{})
	proceed := make(chan struct{})
	var dialed net.Conn
	tr := transport(srv)
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		close(dialing)
		<-proceed
		var d net.Dialer
		c, err := d.DialContext(ctx, network, srv.Addr)
		dialed = c
		return c, err
	}
	errc := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		_, err := tr.RoundTrip(req)
		errc <- err
	}()
	<-dialing
	tr.Close()
	close(proceed)
	if err := <-errc; !errors.Is(err, dispatch.ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
	dialed.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := dialed.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("connection dialed after Close is still open: read err = %v", err)
	}
}
