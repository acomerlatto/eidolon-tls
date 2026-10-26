package tlsdial

import (
	"crypto/tls"

	utls "github.com/acomerlatto/utls"
)

// ConnectionState converts the uTLS connection state into the crypto/tls type
// used by http.Response.TLS. Every exported field of crypto/tls is copied.
//
// PeerApplicationSettings (ALPS) has no crypto/tls equivalent and is dropped;
// read it from the uTLS connection.
//
// ExportKeyingMaterial cannot be rebuilt: crypto/tls keeps the exporter in an
// unexported field, so calling it on the result panics with a nil function
// call. Use the uTLS connection's ConnectionState for keying material; it is
// available only when Config.Renegotiation is RenegotiateNever, even in
// TLS 1.3, and the Chrome spec enables renegotiation.
func ConnectionState(s utls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version:                     s.Version,
		HandshakeComplete:           s.HandshakeComplete,
		DidResume:                   s.DidResume,
		CipherSuite:                 s.CipherSuite,
		CurveID:                     tls.CurveID(s.CurveID),
		NegotiatedProtocol:          s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  s.NegotiatedProtocolIsMutual,
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
		TLSUnique:                   s.TLSUnique,
		ECHAccepted:                 s.ECHAccepted,
		HelloRetryRequest:           s.HelloRetryRequest,
		LocalCertificate:            s.LocalCertificate,
	}
}

// StdConn exposes a uTLS connection with a crypto/tls ConnectionState, so
// code that looks for that method (the HTTP/2 engine fills Response.TLS
// from it) sees the converted state.
type StdConn struct {
	*utls.UConn
}

// ConnectionState returns the converted state; see ConnectionState.
func (c StdConn) ConnectionState() tls.ConnectionState {
	return ConnectionState(c.UConn.ConnectionState())
}
