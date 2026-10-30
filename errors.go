package eidolon

import (
	"errors"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/proxy"
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
	// ErrProfile reports a ClientHello spec that cannot be used: the
	// WithClientHello function failed or returned nil, the spec sets the
	// SNI name, it offers none of the enabled protocols, or uTLS refused
	// to apply it. New checks one spec; a later one that fails is
	// reported by the request, before any connection is opened.
	ErrProfile = tlsdial.ErrProfile
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
	// ErrECHRequired reports a request, with ECHRequired, to an origin
	// without an ECH configuration, from WithECHConfig or its HTTPS record
	// (WithDoH or the name servers of the system), or with none the client
	// can use, or to an http:// URL: no connection to the origin is
	// opened. It also reports, with ErrECHRejected, a server that rejected
	// ECH without usable retry configurations, after that connection.
	ErrECHRequired = dispatch.ErrECHRequired
	// ErrECHRejected reports a server that rejected ECH also on the
	// connection that retried it (see ECHAuto), or, with ECHRequired,
	// without usable retry configurations. The utls.ECHRejectionError
	// stays in the chain; no HTTP byte is sent.
	ErrECHRejected = tlsdial.ErrECHRejected
	// ErrDNS reports, with ECHRequired, an HTTPS record that could not be
	// looked up (WithDoH or the name servers of the system): the server
	// could not be reached, answered SERVFAIL or a malformed response, or
	// not in time. In any mode, it
	// also reports an HTTPS record whose services all have ECH and none an
	// enabled protocol, which Chrome does not connect without. No
	// connection to the origin is opened.
	ErrDNS = dispatch.ErrDNS
	// ErrInvalidECHConfig reports an HTTPS record whose ECHConfigList
	// cannot be read, which fails the request as in Chrome. No connection
	// to the origin is opened.
	ErrInvalidECHConfig = dispatch.ErrInvalidECHConfig
	// ErrProxy reports a proxy (WithProxy) that could not be reached or
	// refused the tunnel; no byte of the request reached the destination.
	ErrProxy = proxy.ErrProxy
	// ErrProxyAuth reports a proxy that refused the credentials of its URL,
	// or asked for credentials the URL does not have.
	ErrProxyAuth = proxy.ErrProxyAuth
	// ErrTLS12Policy reports a TLS 1.2 connection refused by
	// WithStrictTLS12.
	ErrTLS12Policy = tlsdial.ErrTLS12Policy
	// ErrHTTP2InadequateSecurity reports a server that negotiated HTTP/2
	// over TLS 1.2 with a cipher suite HTTP/2 forbids, without AEAD or
	// with RSA key exchange. As Chrome, the client closes the connection
	// with GOAWAY INADEQUATE_SECURITY.
	ErrHTTP2InadequateSecurity = dispatch.ErrHTTP2InadequateSecurity
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
	// the server did not process, as Chrome; one replay after an idle
	// HTTP/2 connection was lost, as the server might have processed it;
	// three replays over HTTP/1.1 or three dials. It wraps the last error.
	ErrRetryBudget = dispatch.ErrRetryBudget
	// ErrTooManyRedirects reports a request stopped after 20 redirects,
	// the limit of the Fetch standard and Chrome.
	ErrTooManyRedirects = errors.New("eidolon: stopped after 20 redirects")
)
