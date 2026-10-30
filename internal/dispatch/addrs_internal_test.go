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

// With Addrs, the TLS connections go to the addresses in turn, with the
// port of the target: a failed connection or handshake goes to the next
// address, each address has an equal share of the time left, and a
// rejected ECH is retried on the same address.
func TestDialAddrs(t *testing.T) {
	defer func(d time.Duration) { dialTimeout = d }(dialTimeout)
	dialTimeout = time.Second
	list, _, err := lab.NewECHKey(1, "public.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := lab.NewCertificate(time.Hour, "secret.test", "public.test")
	if err != nil {
		t.Fatal(err)
	}
	other, err := lab.NewCertificate(time.Hour, "other.test")
	if err != nil {
		t.Fatal(err)
	}
	good := lab.Start(t, lab.Options{Certificate: &cert})
	wrongCert := lab.Start(t, lab.Options{Certificate: &other})
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	refused, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused.Close()

	for _, tt := range []struct {
		name  string
		first string // the server of the first address
		slow  bool   // the second address takes 350ms to connect
		ech   bool
		want  []string
	}{
		{"connection refused", refused.Addr().String(), false, false, []string{"192.0.2.1:443", "192.0.2.2:443"}},
		{"certificate", wrongCert.Addr, false, false, []string{"192.0.2.1:443", "192.0.2.2:443"}},
		{"no answer", silent.Addr().String(), true, false, []string{"192.0.2.1:443", "192.0.2.2:443"}},
		{"ECH rejected", good.Addr, false, true, []string{"192.0.2.1:443", good.Addr}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var dialed []string
			saved := systemDial
			defer func() { systemDial = saved }()
			systemDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				mu.Lock()
				dialed = append(dialed, addr)
				mu.Unlock()
				switch addr {
				case "192.0.2.1:443":
					addr = tt.first
				case "192.0.2.2:443":
					addr = good.Addr
					if tt.slow {
						select {
						case <-time.After(350 * time.Millisecond):
						case <-ctx.Done():
							return nil, ctx.Err()
						}
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
				TLS:   &utls.Config{RootCAs: good.RootCAs},
				Addrs: []string{"192.0.2.1", "192.0.2.2"},
			}
			tr.TLS.RootCAs.AddCert(wrongCert.Certificate)
			if tt.ech {
				tr.ECH = map[string][]byte{"https://secret.test": list}
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
			if !slices.Equal(dialed, tt.want) {
				t.Errorf("dialed %q, want %q", dialed, tt.want)
			}
		})
	}
}
