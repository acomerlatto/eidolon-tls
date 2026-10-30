package eidolon_test

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	eidolon "github.com/acomerlatto/eidolon-tls"
)

// A client with the profile of Chrome 156 on Linux sends requests as that
// browser: its ClientHello, its HTTP/2 settings and its headers, in its
// order. The protocol is negotiated by ALPN, HTTP/2 when the server offers
// it.
func ExampleNew() {
	c, err := eidolon.New(eidolon.WithProfile(eidolon.Chrome156Linux()))
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	resp, err := c.Get("https://example.com/")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp.Proto, resp.Status, len(body))
}

// WithForceHTTP2 offers only h2 in ALPN: a server that does not negotiate
// it fails the request instead of answering over HTTP/1.1, with
// ErrProtocolPolicy when it completes the handshake without ALPN.
func ExampleWithForceHTTP2() {
	c, err := eidolon.New(eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithForceHTTP2())
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	resp, err := c.Get("https://example.com/")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Proto) // HTTP/2.0
}

// A custom profile starts from a built-in one. Here the ClientHello is
// rebuilt from a capture of the browser, with its extensions shuffled on
// each connection as Chrome does, and the HTTP/2 settings come from an
// Akamai fingerprint.
func ExampleProfile() {
	raw, err := os.ReadFile("testdata/chrome156-linux-clienthello.bin")
	if err != nil {
		log.Fatal(err)
	}
	hello, err := eidolon.ClientHelloFromRaw(raw, eidolon.WithShuffledExtensions())
	if err != nil {
		log.Fatal(err)
	}

	p := eidolon.Chrome156Linux()
	p.Name = "chrome/156/linux-captured"
	p.ClientHello = hello
	p.HTTP2, p.PseudoOrder, err = eidolon.ParseAkamai("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", p.HTTP2)
	if err != nil {
		log.Fatal(err)
	}

	c, err := eidolon.New(eidolon.WithProfile(p))
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get("https://example.com/")
	if err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()
}

// In the default mode, ECHAuto, an origin whose HTTPS record carries an ECH
// configuration gets ECH, and the others the GREASE ECH of the profile, as
// Chrome. WithDoH asks the records to a DNS over HTTPS server, here
// Cloudflare's at its IP addresses; without it, a client on Linux asks the
// name servers of the system.
func ExampleWithECHMode_auto() {
	c, err := eidolon.New(
		eidolon.WithProfile(eidolon.Chrome156Linux()),
		eidolon.WithDoH("https://cloudflare-dns.com/dns-query{?dns}", "1.1.1.1", "1.0.0.1"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	resp, err := c.Get("https://crypto.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println("ECH accepted:", resp.TLS.ECHAccepted)
}

// With ECHRequired, a request completes only over a connection whose
// server accepted ECH: an origin without an ECH configuration fails with
// ErrECHRequired before any connection.
func ExampleWithECHMode_required() {
	c, err := eidolon.New(
		eidolon.WithProfile(eidolon.Chrome156Linux()),
		eidolon.WithDoH("https://cloudflare-dns.com/dns-query{?dns}", "1.1.1.1", "1.0.0.1"),
		eidolon.WithECHMode(eidolon.ECHRequired),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	resp, err := c.Get("https://example.com/")
	switch {
	case errors.Is(err, eidolon.ErrECHRequired):
		fmt.Println("no ECH for this origin")
	case err != nil:
		log.Fatal(err)
	default:
		resp.Body.Close()
		fmt.Println("ECH accepted:", resp.TLS.ECHAccepted) // always true
	}
}

// Through a proxy, every connection goes over it; the proxy resolves the
// destination. With WithNewConnectionPerRequest, each request opens its
// own connection, so a rotating proxy can give it another exit.
func ExampleWithProxy() {
	c, err := eidolon.New(
		eidolon.WithProfile(eidolon.Chrome156Linux()),
		eidolon.WithProxy("http://user:password@proxy.example:8080"),
		eidolon.WithNewConnectionPerRequest(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	resp, err := c.Get("https://example.com/")
	if err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()
}
