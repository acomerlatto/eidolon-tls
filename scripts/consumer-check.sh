#!/usr/bin/env bash
# consumer-check.sh [version]
#
# Builds and runs, outside any workspace and with GOWORK=off, a module that
# imports eidolon-tls and sends a request over HTTP/2 to a local server. The
# module is the version given (a tag such as v0.1.0, or a commit), fetched
# through the Go module proxy and checked against the checksum database,
# or, without one, the HEAD of this checkout, fetched from it directly.
set -euo pipefail

mod=github.com/acomerlatto/eidolon-tls
repo=$(cd "$(dirname "$0")/.." && pwd)
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

export GOWORK=off GOFLAGS=-modcacherw
if [[ $# -eq 0 ]]; then
	version=$(git -C "$repo" rev-parse HEAD)
	export GIT_CONFIG_COUNT=1
	export GIT_CONFIG_KEY_0="url.$repo.insteadOf"
	export GIT_CONFIG_VALUE_0="https://$mod"
	export GOPROXY=direct GOPRIVATE=$mod
else
	version=$1
fi

cd "$dir"
go mod init example.com/consumer >/dev/null 2>&1
cat >main.go <<'EOF'
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"

	eidolon "github.com/acomerlatto/eidolon-tls"
)

func main() {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Proto)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	c, err := eidolon.New(
		eidolon.WithProfile(eidolon.Chrome156Linux()),
		eidolon.WithRootCAs(roots),
		eidolon.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		}),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer c.Close()
	// The certificate of httptest is valid for example.com.
	resp, err := c.Get("https://example.com/")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.ProtoMajor != 2 || string(body) != "HTTP/2.0" {
		fmt.Fprintf(os.Stderr, "got %s, server saw %q; want HTTP/2\n", resp.Proto, body)
		os.Exit(1)
	}
	fmt.Println("consumer: HTTP/2 request through", resp.TLS.ServerName)
}
EOF
go get "$mod@$version"
go mod tidy
# The fork of uTLS comes as a module, without a replace directive.
if grep -q replace go.mod; then
	echo "consumer-check: go.mod has a replace directive" >&2
	exit 1
fi
go list -m github.com/acomerlatto/utls "$mod"
go vet ./...
go run .
