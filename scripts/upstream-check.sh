#!/usr/bin/env bash
# upstream-check.sh
#
# Lists what the upstreams of Eidolon changed since the code it uses, for a
# security sync (UPSTREAM.md):
#   - golang.org/x/net, in the packages copied to internal/, since the commit
#     of internal/http2/UPSTREAM.md;
#   - refraction-networking/utls, since the base commit of the fork version
#     in go.mod (the UPSTREAM.md of that module);
#   - the Go toolchain: the version in use and the latest release.
# Commits whose subject looks like a security fix are marked with "!".
#
# The master branches of the upstreams are copied, without file contents, to
# $EIDOLON_UPSTREAM_CACHE (default ~/.cache/eidolon-upstream).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cache=${EIDOLON_UPSTREAM_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/eidolon-upstream}
mkdir -p "$cache"

# mirror name url: prints the path of an up-to-date copy of the master
# branch of url.
mirror() {
	local dir=$cache/$1.git
	if [[ -d $dir ]]; then
		git -C "$dir" fetch -q origin master:master
	else
		git clone -q --bare --single-branch --branch master --filter=blob:none "$2" "$dir"
	fi
	echo "$dir"
}

# changes repo base paths...: the commits of master after base.
changes() {
	local repo=$1 base=$2 branch=master
	shift 2
	local n
	n=$(git -C "$repo" rev-list --count --no-merges "$base..$branch" -- "$@")
	echo "$n commits since ${base:0:12}"
	git -C "$repo" log --no-merges --date=short --format='%h %ad %s' "$base..$branch" -- "$@" |
		awk 'tolower($0) ~ /secur|cve|vuln|denial|dos[^a-z]|panic|crash|overflow|exhaust|excessive|smuggl|limit/ { print "! " $0; next } { print "  " $0 }'
}

echo "== golang.org/x/net (copied in internal/)"
xnet_base=$(awk -F'`' '/^- Commit:/ { print $2; exit }' "$root/internal/http2/UPSTREAM.md")
xnet=$(mirror net https://go.googlesource.com/net)
changes "$xnet" "$xnet_base" http2 internal/httpcommon internal/httpsfv internal/gate internal/testcert

echo
echo "== refraction-networking/utls (fork github.com/acomerlatto/utls)"
utls_dir=$(cd "$root" && GOWORK=off go mod download -json github.com/acomerlatto/utls | awk -F'"' '$2 == "Dir" { print $4 }')
utls_version=$(cd "$root" && GOWORK=off go list -m -f '{{.Version}}' github.com/acomerlatto/utls)
utls_base=$(awk -F'`' '/^- Base commit:/ { print $2; exit }' "$utls_dir/UPSTREAM.md")
echo "fork $utls_version"
utls=$(mirror utls https://github.com/refraction-networking/utls)
changes "$utls" "$utls_base"

echo
echo "== Go toolchain"
echo "in use: $(go env GOVERSION), go.mod: go $(awk '$1 == "go" { print $2; exit }' "$root/go.mod")"
echo "latest: $(curl -fsS 'https://go.dev/VERSION?m=text' | head -n 1)"
