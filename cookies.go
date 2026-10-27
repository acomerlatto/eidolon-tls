package eidolon

import (
	"net/http"
	"net/http/cookiejar"

	"golang.org/x/net/publicsuffix"
)

// NewCookieJar returns an empty cookie jar for WithCookieJar: the jar of
// net/http/cookiejar with the public suffix list, so a cookie cannot be set
// for a whole public suffix such as "co.uk".
func NewCookieJar() http.CookieJar {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return jar
}
