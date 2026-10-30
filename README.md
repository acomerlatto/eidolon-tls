# EIDOLON

A faithful, fingerprint-aware HTTP client for Go.

Don't just look alike. Behave alike.

[Português](README.pt-BR.md)

Eidolon sends HTTP requests the way a real browser does. It copies more than
the fingerprint: the TLS ClientHello, the HTTP/2 settings, frames and
priorities, and the header order and spelling. It also behaves like the
browser: how it uses connections, retries, redirects, resumes TLS sessions,
negotiates Encrypted Client Hello and goes through proxies. Each behavior is
checked against the browser's source and against captures of its traffic.

It is built for crawlers, which usually run behind proxies.

## Install

```sh
go get github.com/acomerlatto/eidolon-tls
```

It needs Go 1.27.2 or later. The TLS stack is a fork of uTLS,
[`github.com/acomerlatto/utls`](https://github.com/acomerlatto/utls),
required as a module: no `replace` directive is needed.

## Use

```go
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
```

The API uses the standard `net/http` types. `c.Transport()` is an
`http.RoundTripper` for code that builds its own `http.Client`.

The [examples](example_test.go) show HTTP/2, a custom profile built from a
captured ClientHello and an Akamai fingerprint, ECH in automatic and required
mode, and a proxy.

## What it reproduces

- **Profile:** Chrome 156 on Linux, built in. Other browsers and versions
  are made with `Profile`, `ClientHelloFromRaw` and `ParseAkamai`.
- **TLS:** TLS 1.3 and 1.2, a new ClientHello for each connection with
  Chrome's extension shuffling and GREASE, and Chrome's TLS session cache.
- **ECH:** in automatic mode (Chrome's default), required or off, with the
  configuration from DNS HTTPS records (the system resolver on Linux, or
  DNS over HTTPS) or set by hand. The ClientHelloInner is built as
  BoringSSL builds it.
- **HTTP/2:** Chrome's SETTINGS, WINDOW_UPDATE, priorities, HPACK, header
  framing, error handling, ALPS and PING behavior.
- **HTTP/1.1:** header order and spelling, connection pooling and limits.
- **Headers:** the profile's headers per request destination
  (`WithFetchDest`), `Sec-Fetch-*` and `Origin` as the Fetch standard sets
  them, and an exact mode that sends only the given fields, in their order.
- **Proxies:** HTTP (CONNECT), HTTPS, SOCKS4/4a and SOCKS5/5h, with one
  connection per request as an option for rotating proxies.
- **Redirects and cookies:** redirects as the Fetch standard and Chrome
  follow them, and an optional cookie jar with the public suffix list.

## Limits

What Eidolon does not do, and where it differs from Chrome, is listed in
[LIMITS.md](LIMITS.md). The main points: no HTTP/3, no revocation checking,
certificates verified against Go's roots, and verified on Linux x86_64 only.

## Upstreams

The HTTP/2 engine is a copy of `golang.org/x/net/http2` with local patches,
and the TLS stack is a fork of uTLS. [UPSTREAM.md](UPSTREAM.md) lists them
and describes how their security fixes reach Eidolon.

## License

MIT, see [LICENSE](LICENSE). The code copied from `golang.org/x/net`, in
`internal/`, keeps its BSD-3-Clause license.
