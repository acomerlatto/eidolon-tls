//go:build interop

// The interoperability tests run Eidolon against servers of other
// implementations, in Docker: nginx, over OpenSSL, and Caddy, over Go's
// crypto/tls and net/http. They are left out of the standard suite; run
// them with
//
//	go test -tags interop -run Interop -timeout 600s .
//
// Each server offers three ports: HTTP/2 and HTTP/1.1 over TLS 1.2 and
// 1.3, HTTP/1.1 alone, and TLS 1.2 alone; nginx a fourth, which sends a
// GOAWAY after two requests.

package eidolon_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

const (
	interopNginx = "nginx:1.30.6-alpine"
	interopCaddy = "caddy:2.11.7-alpine"
	// interopHost is the name of the servers; interopPublic is the public
	// name of Caddy's ECH configuration.
	interopHost   = "interop.test"
	interopPublic = "public.test"
)

// interopPorts are the ports inside the container: both protocols, HTTP/1.1
// alone, and TLS 1.2 alone.
var interopPorts = []string{"8443", "8444", "8445"}

const interopNginxConf = `
worker_processes 1;
events {}
http {
	ssl_certificate     /etc/interop/cert.pem;
	ssl_certificate_key /etc/interop/key.pem;
	gzip on;
	gzip_types *;
	gzip_min_length 0;
	http2_max_concurrent_streams 4;
	server {
		listen 8443 ssl;
		http2 on;
		include /etc/interop/site.conf;
	}
	server {
		listen 8444 ssl;
		include /etc/interop/site.conf;
	}
	server {
		listen 8445 ssl;
		http2 on;
		ssl_protocols TLSv1.2;
		include /etc/interop/site.conf;
	}
	server {
		# A GOAWAY after two requests on a connection.
		listen 8446 ssl;
		http2 on;
		keepalive_requests 2;
		include /etc/interop/site.conf;
	}
	server {
		listen 127.0.0.1:8080;
		location / { return 200 "$http_content_length $http_content_type"; }
	}
}
`

// interopNginxSite is the site of every nginx port: the files of www,
// and /echo, which a backend answers with the Content-Length and
// Content-Type it received.
const interopNginxSite = `
root /etc/interop/www;
location /echo { proxy_pass http://127.0.0.1:8080; }
`

const interopCaddyfile = `{
	admin off
	auto_https off
	ech ` + interopPublic + `
	servers {
		protocols h1 h2
	}
	servers :8444 {
		protocols h1
	}
}
(site) {
	encode zstd gzip
	root * /etc/interop/www
	file_server
	handle /echo {
		respond "{http.request.header.Content-Length} {http.request.header.Content-Type} {http.request.body}"
	}
}
https://` + interopHost + `:8443, https://` + interopPublic + `:8443 {
	tls /etc/interop/cert.pem /etc/interop/key.pem
	import site
}
https://` + interopHost + `:8444 {
	tls /etc/interop/cert.pem /etc/interop/key.pem
	import site
}
https://` + interopHost + `:8445 {
	tls /etc/interop/cert.pem /etc/interop/key.pem {
		protocols tls1.2 tls1.2
	}
	import site
}
`

// interopServer is a server in a container.
type interopServer struct {
	name string
	// addrs are the host addresses of the ports in the container.
	addrs map[string]string
	roots *x509.CertPool
	// big is the body of /big.
	big []byte
}

// startInterop starts image with files mounted on /etc/interop and args as
// its command, and waits for interopPorts and extra to answer.
func startInterop(t *testing.T, name, image string, files map[string]string, extra []string, args ...string) *interopServer {
	t.Helper()
	dir := t.TempDir()
	cert, err := lab.NewCertificate(time.Hour, interopHost, interopPublic)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	// /big is compressible text of 1 MiB, so the servers compress it.
	var big bytes.Buffer
	for i := 0; big.Len() < 1<<20; i++ {
		fmt.Fprintf(&big, "line %d of the interop body\n", i)
	}
	all := map[string]string{
		"cert.pem":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Leaf.Raw})),
		"key.pem":   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
		"www/big":   big.String(),
		"www/small": "ok",
	}
	for f, content := range files {
		all[f] = content
	}
	for f, content := range all {
		path := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The container reads the files as another user.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	ports := append(slices.Clone(interopPorts), extra...)
	run := []string{"run", "-d", "--name", name, "-v", dir + ":/etc/interop:ro"}
	for _, p := range ports {
		run = append(run, "-p", "127.0.0.1::"+p)
	}
	run = append(append(run, image), args...)
	exec.Command("docker", "rm", "-f", "-v", name).Run()
	if out, err := exec.Command("docker", run...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Logf("%s logs:\n%s", name, out)
		}
		exec.Command("docker", "rm", "-f", "-v", name).Run()
	})

	srv := &interopServer{name: name, addrs: map[string]string{}, roots: x509.NewCertPool(), big: big.Bytes()}
	srv.roots.AddCert(cert.Leaf)
	for _, p := range ports {
		out, err := exec.Command("docker", "port", name, p+"/tcp").Output()
		if err != nil {
			t.Fatalf("docker port %s: %v", p, err)
		}
		srv.addrs[p] = strings.TrimSpace(strings.Split(string(out), "\n")[0])
	}
	deadline := time.Now().Add(30 * time.Second)
	for _, p := range ports {
		for {
			conn, err := tls.Dial("tcp", srv.addrs[p], &tls.Config{ServerName: interopHost, RootCAs: srv.roots})
			if err == nil {
				conn.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("port %s does not answer: %v", p, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return srv
}

// client returns a Chrome client of srv: every connection goes to the host
// address of the port of its URL.
func (srv *interopServer) client(t *testing.T, opts ...eidolon.Option) eidolon.HttpClient {
	t.Helper()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var d net.Dialer
		return d.DialContext(ctx, network, srv.addrs[port])
	}
	base := []eidolon.Option{eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithRootCAs(srv.roots), eidolon.WithDialContext(dial)}
	c, err := eidolon.New(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// interopGet sends a GET to url and returns the response with its body
// read.
func interopGet(t *testing.T, c eidolon.HttpClient, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: body: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	return resp, body
}

// testInterop runs the checks common to the servers on srv.
func testInterop(t *testing.T, srv *interopServer) {
	ports := []struct {
		port    string
		proto   string
		version uint16
	}{
		{"8443", "HTTP/2.0", tls.VersionTLS13},
		{"8444", "HTTP/1.1", tls.VersionTLS13},
		{"8445", "HTTP/2.0", tls.VersionTLS12},
	}
	for _, p := range ports {
		base := fmt.Sprintf("https://%s:%s", interopHost, p.port)
		t.Run(p.port, func(t *testing.T) {
			// The protocol and the version; a body compressed by the
			// server, decompressed whole; a POST body received whole.
			t.Run("Exchange", func(t *testing.T) {
				c := srv.client(t)
				resp, body := interopGet(t, c, base+"/small")
				if resp.Proto != p.proto || resp.TLS.Version != p.version || string(body) != "ok" {
					t.Errorf("%s, %s, body %q; want %s, %s, ok", resp.Proto, tls.VersionName(resp.TLS.Version), body, p.proto, tls.VersionName(p.version))
				}
				resp, body = interopGet(t, c, base+"/big")
				if !resp.Uncompressed || sha256.Sum256(body) != sha256.Sum256(srv.big) {
					t.Errorf("/big: uncompressed %v, %d bytes; want a compressed body of %d bytes", resp.Uncompressed, len(body), len(srv.big))
				}
				payload := `{"a":1}`
				resp, err := c.Post(base+"/echo", "application/json", strings.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				body, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if want := fmt.Sprintf("%d application/json", len(payload)); !strings.HasPrefix(string(body), want) {
					t.Errorf("/echo: %q, want %q first", body, want)
				}
			})
			// The connection after the first resumes the session.
			t.Run("Resumption", func(t *testing.T) {
				c := srv.client(t)
				var got []bool
				for range 3 {
					resp, _ := interopGet(t, c, base+"/small")
					got = append(got, resp.TLS.DidResume)
					c.CloseIdleConnections()
				}
				if got[0] || !got[1] || !got[2] {
					t.Errorf("resumed %v, want [false true true]", got)
				}
			})
			// Concurrent requests share the connections and all succeed.
			t.Run("Concurrent", func(t *testing.T) {
				c := srv.client(t)
				var wg sync.WaitGroup
				for range 20 {
					wg.Go(func() {
						resp, err := c.Get(base + "/big")
						if err != nil {
							t.Error(err)
							return
						}
						defer resp.Body.Close()
						body, err := io.ReadAll(resp.Body)
						if err != nil || !bytes.Equal(body, srv.big) {
							t.Errorf("%d bytes, %v", len(body), err)
						}
					})
				}
				wg.Wait()
			})
		})
	}
}

func TestInteropNginx(t *testing.T) {
	srv := startInterop(t, "eidolon-interop-nginx", interopNginx, map[string]string{
		"nginx.conf": interopNginxConf,
		"site.conf":  interopNginxSite,
	}, []string{"8446"}, "nginx", "-c", "/etc/interop/nginx.conf", "-g", "daemon off;")
	testInterop(t, srv)
	// On port 8446, nginx closes a connection with a GOAWAY after two
	// requests: the following ones go on new connections. With many
	// requests at once, some run out of retries, as in Chrome: the
	// requests waiting for a stream when the GOAWAY comes fail with
	// ERR_HTTP2_SERVER_REFUSED_STREAM, sent again at most
	// kMaxRetryAttempts times.
	t.Run("GOAWAY", func(t *testing.T) {
		c := srv.client(t)
		for i := range 7 {
			if _, body := interopGet(t, c, "https://"+interopHost+":8446/small"); string(body) != "ok" {
				t.Errorf("request %d: %q", i, body)
			}
		}
	})
}

func TestInteropCaddy(t *testing.T) {
	srv := startInterop(t, "eidolon-interop-caddy", interopCaddy, map[string]string{
		"Caddyfile": interopCaddyfile,
	}, nil, "caddy", "run", "--config", "/etc/interop/Caddyfile")
	testInterop(t, srv)
	// Caddy offers ECH with a configuration it generates; the connections
	// to interopHost with it accept ECH and resume with it.
	t.Run("ECH", func(t *testing.T) {
		out, err := exec.Command("docker", "exec", srv.name, "sh", "-c", "cat /data/caddy/ech/configs/*/config.bin").Output()
		if err != nil || len(out) == 0 {
			t.Fatalf("ECH configuration of Caddy: %v", err)
		}
		list := binary.BigEndian.AppendUint16(nil, uint16(len(out)))
		list = append(list, out...)
		c := srv.client(t, eidolon.WithECHConfig(interopHost+":8443", list))
		var got []bool
		for range 3 {
			resp, _ := interopGet(t, c, "https://"+interopHost+":8443/small")
			if !resp.TLS.ECHAccepted {
				t.Fatal("ECH not accepted")
			}
			got = append(got, resp.TLS.DidResume)
			c.CloseIdleConnections()
		}
		if got[0] || !got[1] || !got[2] {
			t.Errorf("resumed %v, want [false true true]", got)
		}
	})
}
