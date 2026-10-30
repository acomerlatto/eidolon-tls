# Upstreams

Eidolon is built on code it does not own. A fix upstream, security fixes
included, reaches Eidolon only through the steps below.

| Code | Upstream | How Eidolon uses it | Record |
|---|---|---|---|
| HTTP/2 engine: `internal/http2`, `hpack`, `httpcommon`, `httpsfv` | `golang.org/x/net` | Copied by `scripts/sync-xnet.sh` from a commit of the fork `github.com/acomerlatto/net`, with the patches of `scripts/xnet-patches` | [`internal/http2/UPSTREAM.md`](internal/http2/UPSTREAM.md) |
| TLS: ClientHello, handshake, ECH | `refraction-networking/utls`, itself a copy of Go's `crypto/tls` | The fork `github.com/acomerlatto/utls`, a module required by `go.mod` | `UPSTREAM.md` of the fork |
| `net/http` types, `crypto/x509`, `net` | Go | The toolchain that builds the consumer; `go.mod` sets the minimum | `go.mod` |

## When to sync

- A Go security release, or an advisory on golang-announce, about
  `net/http`, `golang.org/x/net/http2`, `crypto/tls` or `crypto/x509`.
- A security advisory or release of uTLS.
- Before each release of Eidolon.

## Procedure

1. Run `scripts/upstream-check.sh`. It lists the commits of x/net in the
   copied packages since the copy, the commits of uTLS since the base of the
   fork version in `go.mod`, and the Go version in use against the latest.
   Commits that look like security fixes are marked with `!`; read them all
   anyway.
2. **x/net.** In the fork `github.com/acomerlatto/net`, fetch
   `https://go.googlesource.com/net` and fast-forward `master` to the commit
   with the fix. Run `scripts/sync-xnet.sh ../net`: a patch that no longer
   applies stops it, and is rewritten from a `git diff` of the new copy.
   Set `golang.org/x/net` in `go.mod` to the same commit, since `idna` and
   `http/httpguts` come from it. Commit as `build(xnet): sync to <commit>`.
3. **uTLS.** In the fork, merge the upstream as its `UPSTREAM.md` says, run
   its tests, update its base commit and tag the next version. In Eidolon,
   `go get github.com/acomerlatto/utls@<version>`. A fix in Go's
   `crypto/tls` does not reach uTLS with a new Go version: uTLS is a copy.
   Check whether the fix applies to the fork's code; if upstream uTLS has
   not ported it, port it as a patch of the fork, with its test.
4. **Go.** Build and test with the latest patch release. Raise the `go`
   line of `go.mod` only when Eidolon needs that release: it is the minimum
   every consumer must have.
5. Run the full suite with `-race` and `GOWORK=off`, the interoperability
   tests (`go test -tags interop -run Interop -timeout 600s .`), tag a
   patch release, and run `scripts/consumer-check.sh <tag>`.
