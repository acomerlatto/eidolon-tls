package dispatch

import (
	"context"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// Without DialContext, the connection after an ECH rejection goes to the
// address of the rejected one, as Chrome's TlsStreamAttempt, not to a new
// resolution of the host name, which may give a server of another ECH
// configuration (RFC 9849, Section 6.1.6).
func TestECHRetrySameAddress(t *testing.T) {
	list, _, err := lab.NewECHKey(1, "public.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := lab.NewCertificate(time.Hour, "secret.test", "public.test")
	if err != nil {
		t.Fatal(err)
	}
	// A server without ECH keys rejects ECH and sends no retry
	// configurations: the retry sends GREASE ECH.
	rejecting := lab.Start(t, lab.Options{Certificate: &cert})
	other := lab.Start(t, lab.Options{Certificate: &cert})

	var mu sync.Mutex
	var dialed []string
	saved := systemDial
	defer func() { systemDial = saved }()
	systemDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		n := len(dialed)
		mu.Unlock()
		// The first resolution of the host name gives the rejecting
		// server, the next ones the other server.
		if addr == "secret.test:443" {
			addr = other.Addr
			if n == 1 {
				addr = rejecting.Addr
			}
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	tr := &Transport{
		Spec: func() (*utls.ClientHelloSpec, error) {
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
			return &spec, err
		},
		TLS: &utls.Config{RootCAs: rejecting.RootCAs},
		ECH: map[string][]byte{"https://secret.test": list},
	}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://secret.test/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"secret.test:443", rejecting.Addr}; !slices.Equal(dialed, want) {
		t.Errorf("dialed %q, want %q", dialed, want)
	}
	if n := rejecting.Accepted(); n != 2 {
		t.Errorf("rejecting server: %d connections, want 2", n)
	}
	if n := other.Accepted(); n != 0 {
		t.Errorf("other server: %d connections, want 0", n)
	}
}

// With DialContext, the connection after an ECH rejection gets the
// authority again, which the function resolves as it does, through a
// proxy for instance.
func TestECHRetryDialContext(t *testing.T) {
	list, _, err := lab.NewECHKey(1, "public.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := lab.NewCertificate(time.Hour, "secret.test", "public.test")
	if err != nil {
		t.Fatal(err)
	}
	rejecting := lab.Start(t, lab.Options{Certificate: &cert})
	var mu sync.Mutex
	var dialed []string
	tr := &Transport{
		Spec: func() (*utls.ClientHelloSpec, error) {
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
			return &spec, err
		},
		TLS: &utls.Config{RootCAs: rejecting.RootCAs},
		ECH: map[string][]byte{"https://secret.test": list},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, network, rejecting.Addr)
		},
	}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://secret.test/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"secret.test:443", "secret.test:443"}; !slices.Equal(dialed, want) {
		t.Errorf("dialed %q, want %q", dialed, want)
	}
}
