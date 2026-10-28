package eidolon

import (
	"errors"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// Errors returned by the client, wrapped with context. Test them with
// errors.Is; http.Client wraps transport errors in *url.Error, which
// unwraps to them.
var (
	// ErrConfig reports an invalid option or a missing required one.
	ErrConfig = errors.New("eidolon: invalid configuration")
	// ErrClosed reports a request on a closed client.
	ErrClosed = dispatch.ErrClosed
	// ErrALPN reports a protocol negotiated by ALPN that no engine handles.
	ErrALPN = tlsdial.ErrALPN
	// ErrProtocolPolicy reports a protocol outside the ones enabled by
	// WithProtocols or WithForceHTTP*: negotiated by the server, required
	// by it (HTTP_1_1_REQUIRED), or needed by the URL (http:// needs
	// HTTP/1.1).
	ErrProtocolPolicy = dispatch.ErrProtocolPolicy
	// ErrExactHeadersRedirect reports a redirect of a request sent with
	// WithExactHeaders; see there.
	ErrExactHeadersRedirect = dispatch.ErrExactHeadersRedirect
	// ErrCertificate reports a server certificate refused by verification:
	// unknown authority, wrong name, expired. The crypto/x509 error stays
	// in the chain, for errors.As with x509.UnknownAuthorityError,
	// x509.HostnameError or x509.CertificateInvalidError.
	ErrCertificate = tlsdial.ErrCertificate
	// ErrMalformedResponse reports an HTTP/1.1 response that cannot be
	// read: a bad status line or header, conflicting Content-Length
	// values, more than five 1xx responses. A connection lost while
	// reading is not one.
	ErrMalformedResponse = http1.ErrMalformedResponse
	// ErrHeaderTooLarge reports response headers over the limit, 256 KiB
	// as Chrome, over HTTP/1.1 (1xx responses included) and HTTP/2.
	ErrHeaderTooLarge = http1.ErrHeaderTooLarge
	// ErrRetryBudget reports a request that could have been sent again
	// but was not, because its budget ran out: two retries of a request
	// the server did not process, as Chrome, or three replays after lost
	// connections or three dials. It wraps the last error.
	ErrRetryBudget = dispatch.ErrRetryBudget
	// ErrTooManyRedirects reports a request stopped after 20 redirects,
	// the limit of the Fetch standard and Chrome.
	ErrTooManyRedirects = errors.New("eidolon: stopped after 20 redirects")
)
