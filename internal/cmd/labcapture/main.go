// Command labcapture records what a real browser sends, for the profiles
// of M2. It serves a page from three lab servers at once (h2 and
// http/1.1, http/1.1 only, and plain http://) and writes one JSON file per
// connection when it closes: the raw ClientHello, the TLS state, the
// HTTP/2 frames decoded and the raw bytes after the handshake.
//
// It prints the browser command line. The browser trusts the lab
// certificate by its key hash and resolves the lab names to 127.0.0.1, so
// nothing changes on the system; the URLs use the default ports, as in a
// real visit. Stop it with Ctrl-C: open connections are closed and
// written.
//
// With -doh, a fourth server is the DNS over HTTPS server of the browser,
// in secure mode, and its queries are recorded too: it offers h2 and
// http/1.1, or http/1.1 only with -doh http/1.1. It answers A queries of
// the lab names with 127.0.0.1, HTTPS queries with a record for h2, and
// the other names with NXDOMAIN; the page of DoHSiteHost, on the port of
// the first server, is found through it. With -ech too, that HTTPS record
// carries an ECHConfigList whose key the first server has, so the browser
// connects to DoHSiteHost with ECH; the log has the extension types of
// each ClientHelloInner.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

const (
	hostBoth  = lab.SiteHost
	hostH1    = lab.SiteH1Host
	hostPlain = lab.SitePlainHost
	// hostDoH is the DoH server, and hostDoHSite a name of the first
	// server that only the DoH server resolves.
	hostDoH     = "doh.lab.test"
	hostDoHSite = "dns.lab.test"
	// hostECHPublic is the public name of the ECH configuration.
	hostECHPublic = "public.lab.test"
)

func main() {
	out := flag.String("out", "lab-captures", "directory for the captures")
	port := flag.Int("port", 8443, "first of three consecutive ports, four with -doh")
	doh := flag.String("doh", "", `serve the DoH server of the browser: "h2" (h2 and http/1.1) or "http/1.1"`)
	ech := flag.Bool("ech", false, "with -doh, give the first server an ECH key and its HTTPS record the ECHConfigList")
	flag.Parse()
	if *ech && *doh == "" {
		log.Fatal("-ech needs -doh")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	cert, err := lab.NewCertificate(24*time.Hour, hostBoth, hostH1, hostDoH, hostDoHSite, hostECHPublic)
	if err != nil {
		log.Fatal(err)
	}
	// cert.pem lets a client of the lab, such as Eidolon, trust it.
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Leaf.Raw})
	if err := os.WriteFile(filepath.Join(*out, "cert.pem"), pemCert, 0o644); err != nil {
		log.Fatal(err)
	}

	first := lab.Options{Certificate: &cert}
	var echList []byte
	if *ech {
		list, key, err := lab.NewECHKey(1, hostECHPublic)
		if err != nil {
			log.Fatal(err)
		}
		echList = list
		first.TLS = func(c *tls.Config) {
			c.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{key}
			c.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				log.Printf("ClientHello %s from %s: extensions %v", chi.ServerName, chi.Conn.RemoteAddr(), chi.Extensions)
				return nil, nil
			}
		}
	}
	servers := []struct {
		host string
		opts lab.Options
	}{
		{hostBoth, first},
		{hostH1, lab.Options{Certificate: &cert, NextProtos: []string{"http/1.1"}}},
		{hostPlain, lab.Options{Plain: true}},
	}
	switch *doh {
	case "":
	case "h2", "http/1.1":
		opts := lab.Options{Certificate: &cert, Handler: dohHandler(*port, echList)}
		if *doh == "http/1.1" {
			opts.NextProtos = []string{"http/1.1"}
		}
		servers = append(servers, struct {
			host string
			opts lab.Options
		}{hostDoH, opts})
	default:
		log.Fatalf("-doh %q: want h2 or http/1.1", *doh)
	}
	var (
		seq     atomic.Int32
		quit    = make(chan struct{})
		writers sync.WaitGroup
		running []*lab.Server
		rules   string
	)
	for i, s := range servers {
		if s.opts.Handler == nil {
			s.opts.Handler = lab.Site()
		}
		addr := fmt.Sprintf("127.0.0.1:%d", *port+i)
		srv, err := lab.Listen(addr, s.opts)
		if err != nil {
			log.Fatal(err)
		}
		running = append(running, srv)
		if rules != "" {
			rules += ", "
		}
		rules += fmt.Sprintf("MAP %s %s", s.host, addr)
		writers.Go(func() {
			var conns sync.WaitGroup
			defer conns.Wait()
			handle := func(c *lab.Conn) {
				n := seq.Add(1)
				conns.Go(func() {
					<-c.Done()
					write(*out, n, s.host, c)
				})
			}
			for {
				select {
				case c := <-srv.Conns():
					handle(c)
				case <-quit:
					// The server is closed: every connection is in
					// the channel already.
					for {
						select {
						case c := <-srv.Conns():
							handle(c)
						default:
							return
						}
					}
				}
			}
		})
	}

	spki := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	fmt.Printf(`Lab ready; captures go to %s.

Start the browser with a profile used only for captures, opened once
before so its field trials are loaded, and visit https://%s/:

  google-chrome --user-data-dir=PROFILE \
    --host-resolver-rules=%q \
    --ignore-certificate-errors-spki-list=%s \
    https://%s/

Record chrome://version with each capture. Ctrl-C ends.
`, *out, hostBoth, rules, base64.StdEncoding.EncodeToString(spki[:]), hostBoth)
	if *doh != "" {
		fmt.Printf(`
For DoH, set in the Local State file of the profile, browser closed:

  "dns_over_https": {"mode": "secure", "templates": "https://%s/dns-query{?dns}"}

and visit https://%s:%d/ instead, which only the DoH server resolves.
`, hostDoH, hostDoHSite, *port)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	for _, srv := range running {
		srv.Close() // closes the connections and waits for them
	}
	close(quit)
	writers.Wait()
}

// capture is the JSON form of one connection.
type capture struct {
	Server     string `json:"server"`
	Time       string `json:"time"`
	ALPN       string `json:"alpn,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	// ServerName is the name the server read, of ClientHelloInner with
	// ECH accepted.
	ServerName  string `json:"server_name,omitempty"`
	ECHAccepted bool   `json:"ech_accepted,omitempty"`
	DidResume   bool   `json:"did_resume,omitempty"`
	ClientHello string `json:"client_hello,omitempty"` // hex, handshake message
	// ClientHelloRecord is ClientHello in one TLS record, hex, the input
	// of utls.Fingerprinter.
	ClientHelloRecord string        `json:"client_hello_record,omitempty"`
	HandshakeError    string        `json:"handshake_error,omitempty"`
	H2Frames          []lab.H2Frame `json:"h2_frames,omitempty"`
	H2Error           string        `json:"h2_error,omitempty"`
	// HTTP1 holds the raw requests of an HTTP/1.1 connection.
	HTTP1 string `json:"http1,omitempty"`
	// Stream is every byte after the handshake, base64; HPACK indexing
	// is read from it.
	Stream []byte `json:"stream"`
}

func write(dir string, n int32, host string, c *lab.Conn) {
	cp := capture{
		Server:            host,
		Time:              time.Now().UTC().Format(time.RFC3339),
		ClientHello:       hex.EncodeToString(c.ClientHello),
		ClientHelloRecord: hex.EncodeToString(c.ClientHelloRecord),
		Stream:            c.Bytes(),
	}
	if c.HandshakeErr != nil {
		cp.HandshakeError = c.HandshakeErr.Error()
	}
	proto := "plain"
	if c.State.HandshakeComplete {
		cp.ALPN = c.State.NegotiatedProtocol
		cp.TLSVersion = tls.VersionName(c.State.Version)
		cp.Cipher = tls.CipherSuiteName(c.State.CipherSuite)
		cp.ServerName = c.State.ServerName
		cp.ECHAccepted = c.State.ECHAccepted
		cp.DidResume = c.State.DidResume
		proto = cp.ALPN
		if proto == "" {
			proto = "none"
		}
	}
	if proto == "h2" {
		frames, err := c.H2Frames()
		cp.H2Frames = frames
		if err != nil {
			cp.H2Error = err.Error()
		}
	} else if c.HandshakeErr == nil {
		cp.HTTP1 = string(cp.Stream)
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		log.Print(err)
		return
	}
	name := filepath.Join(dir, fmt.Sprintf("%03d-%s-%s.json", n, host, strings.ReplaceAll(proto, "/", "")))
	if err := os.WriteFile(name, data, 0o644); err != nil {
		log.Print(err)
		return
	}
	log.Printf("wrote %s", name)
}
