# Limits

[Português](LIMITS.pt-BR.md)

What Eidolon does not do, and where it knowingly differs from the browser it
reproduces. Each item was checked against Chrome 156 (its source and captures
of its traffic); the behavior described here is the one of this version.

## Protocols

- TLS 1.3 and 1.2; HTTP/2 and HTTP/1.1, over TLS and over `http://`.
- **No HTTP/3 or QUIC.** Chrome moves to h3 after an `Alt-Svc` or an HTTPS
  record; Eidolon stays on h2 or HTTP/1.1. `WithDisableHTTP3` changes
  nothing yet.
- Not supported: TLS 0-RTT, WebSocket and other upgrades, HTTP/1.1
  pipelining, streaming uploads, trailers.
- No connection coalescing: each origin has its own connections, where
  Chrome may share an HTTP/2 connection between origins with the same IP
  address and certificate.
- No preconnect: a library has no predictor.

## Profiles

- One built-in profile: Chrome 156 on Linux (`Chrome156Linux`). Other
  versions and browsers are made with `Profile` and `ClientHelloFromRaw`;
  only the built-in one was measured against the browser.
- Known differences of `Chrome156Linux` with Chrome 156:
  - the favicon is sent with the priority of an image (`u=2, i`); Chrome
    sent `u=1, i`;
  - the place of some headers in the order of a navigation was not
    captured (`content-length`, `cache-control`, `origin`, `content-type`);
    headers of the caller the profile does not order go last, in
    alphabetical order;
  - `http://localhost` is treated as insecure; Chrome treats it as
    potentially trustworthy and sends `Sec-Fetch-*` and client hints;
  - a navigation without an initiator sends no `Origin`, not even a POST;
  - `sec-fetch-storage-access` is not modeled, and the ACCEPT_CH frame of
    ALPS does not feed client hints.
- HTTP/2 follows Chrome's framing, priorities, flow control and error
  handling (`HTTP2Settings`), with a few error paths that differ in detail:
  a SETTINGS frame of bad length sends GOAWAY without applying the settings
  before it; a response that ends while the body is being sent resets the
  stream with NO_ERROR; the ID of a stream that fails before its HEADERS is
  skipped. Chrome's periodic connection check (PING on a network change)
  is not modeled.
- An HTTPS proxy is offered ALPN `http/1.1` only; Chrome also offers `h2`
  and tunnels over HTTP/2 streams. Proxy credentials go from the first
  request, where Chrome waits for a 407. SOCKS5 also offers user/password
  when credentials are given, which Chrome does not support.
- Behind a proxy, ECH is used as Chrome uses it on a direct connection: the
  HTTPS record is looked up over DNS over HTTPS through the proxy. Chrome
  behind a proxy sends only GREASE ECH.

## DNS

- Only HTTPS records are looked up, for ECH; addresses come from the proxy,
  `WithDialContext` or the system resolver. There is no Happy Eyeballs, no
  search list and no adaptive fallback of Chrome's own resolver.
- Without `WithDoH`, HTTPS records come from the name servers of
  `/etc/resolv.conf`, on Linux only, and only on a direct connection. On
  other systems, through a proxy or `WithDialContext`, only `WithECHConfig`
  gives ECH configurations.
- DNS over HTTPS does not follow redirects; Chrome follows those to
  `https://`.

## TLS session resumption

Sessions are kept as Chrome keeps them (see the package documentation), with
these differences:

- TLS 1.2 resumes by session ticket only, not by session ID: Go's
  `crypto/tls` does not resume by ID.
- The age of a ticket is computed before the TCP dial; Chrome computes it
  after.
- An expired second session of an origin is dropped when it is looked up,
  not before.
- The cache key is the origin, or the address of the HTTPS proxy. Chrome's
  key also has the network anonymization key, the privacy mode, the session
  usage and the proxy chain; in Eidolon the cache belongs to one client,
  which has one proxy.
- With `WithNewConnectionPerRequest`, no session is kept.

## Certificates and revocation

- Certificates are verified by Go's `crypto/x509` against the system roots,
  or those of `WithRootCAs`, not against Chrome's root store. Some
  certificates Chrome accepts may fail, and the reverse.
- **No revocation checking**: no CRLSet, no OCSP. A stapled OCSP response
  and the signed certificate timestamps are available in `Response.TLS` but
  not checked, and Certificate Transparency is not enforced.
- When verification fails and the server announced its trust anchors,
  Chrome retries asking for one of them (Trust Anchor IDs); Eidolon does
  not.
- `Response.TLS.ExportKeyingMaterial` cannot reach the connection and
  panics if called.

## Resources

- No limit on the total number of connections by default; Chrome has 256 per
  pool. `WithMaxConns` sets one.
- At most 64 HTTPS record lookups at once per client, as Chrome
  (`WithMaxDNSQueries`).

## Platforms

- Verified on Linux x86_64 only. Windows, macOS, arm64, 32-bit systems and
  IPv6 networks were not verified. Apart from the system DNS lookup, which
  exists only on Linux, nothing depends on the system.
