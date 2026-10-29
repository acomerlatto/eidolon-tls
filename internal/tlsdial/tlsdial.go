// Package tlsdial opens TLS connections with a uTLS ClientHello spec.
//
// Dial owns the connection until it returns it: on any error the TCP
// connection is closed, so no HTTP byte can be written on a connection that
// failed TLS or ALPN.
package tlsdial

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"

	utls "github.com/acomerlatto/utls"
)

// Protocols negotiated by ALPN that the HTTP engines handle. An empty
// protocol means the server did not negotiate ALPN and is served by HTTP/1.1.
const (
	ProtoH2    = "h2"
	ProtoHTTP1 = "http/1.1"
)

// ErrALPN reports a protocol negotiated by ALPN that no engine handles.
var ErrALPN = errors.New("tlsdial: unsupported ALPN protocol")

// ErrCertificate reports a server certificate refused by verification:
// unknown authority, wrong name, expired. The crypto/x509 error stays in
// the chain.
var ErrCertificate = errors.New("eidolon: certificate verification failed")

// ErrTLS12Policy reports a TLS 1.2 connection that StrictTLS12 refuses:
// a cipher suite without ECDHE and AEAD, or a server without extended
// master secret or secure renegotiation. The connection is closed after
// the handshake, before any HTTP byte.
var ErrTLS12Policy = errors.New("eidolon: TLS 1.2 connection below the strict policy")

// ErrProfile reports a ClientHello spec that cannot be used: its function
// failed or returned nil, it sets the SNI name, or uTLS refused to apply
// it. No connection is opened for it.
var ErrProfile = errors.New("eidolon: invalid ClientHello profile")

// Config describes how to dial one destination.
type Config struct {
	// Spec returns a new ClientHello spec. It is called once per
	// connection. Its SNI extension must leave ServerName empty: the name
	// comes from TLS.ServerName.
	Spec func() (*utls.ClientHelloSpec, error)

	// TLS holds ServerName, RootCAs and the other verification settings.
	// It is cloned for every connection. ServerName is required.
	TLS *utls.Config

	// DialContext opens the TCP connection. Nil uses a zero net.Dialer.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// StrictTLS12 refuses a TLS 1.2 connection with a cipher suite
	// without ECDHE and AEAD, or a server without extended master secret
	// or secure renegotiation (RFC 9325), with ErrTLS12Policy. Chrome
	// accepts all of them; the ClientHello does not change.
	StrictTLS12 bool
}

// Dial opens a TCP connection to addr, performs the TLS handshake with a new
// spec and checks the negotiated ALPN protocol. The returned connection has
// completed the handshake; its protocol is ConnectionState().NegotiatedProtocol.
//
// Renegotiation follows the spec (its renegotiation_info extension) over
// HTTP/1.1 and without ALPN, and is refused over HTTP/2 (RFC 9113 section
// 9.2.1), as Chrome does.
func Dial(ctx context.Context, network, addr string, cfg Config) (*utls.UConn, error) {
	if cfg.Spec == nil {
		return nil, errors.New("tlsdial: Config.Spec is nil")
	}
	if cfg.TLS == nil || cfg.TLS.ServerName == "" {
		return nil, errors.New("tlsdial: Config.TLS.ServerName is empty")
	}
	if ip, err := netip.ParseAddr(cfg.TLS.ServerName); err == nil && !cfg.TLS.InsecureSkipVerify {
		tc := cfg.TLS.Clone()
		tc.VerifyConnection = exactIP(ip, tc.VerifyConnection)
		cfg.TLS = tc
	}
	// Apply the spec before dialing, so a bad profile opens no connection.
	uconn, tc, err := prepare(cfg)
	if err != nil {
		return nil, err
	}
	dial := cfg.DialContext
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	conn, err := dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uconn.SetUnderlyingConn(conn)
	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		var ve *utls.CertificateVerificationError
		var he x509.HostnameError
		if errors.As(err, &ve) || errors.As(err, &he) {
			err = fmt.Errorf("%w: %w", ErrCertificate, err)
		}
		return nil, err
	}
	st := uconn.ConnectionState()
	switch st.NegotiatedProtocol {
	case ProtoH2, ProtoHTTP1, "":
	default:
		uconn.Close()
		return nil, fmt.Errorf("%w: %q", ErrALPN, st.NegotiatedProtocol)
	}
	if cfg.StrictTLS12 && st.Version == utls.VersionTLS12 {
		if err := strictTLS12(st.CipherSuite, uconn.HandshakeState.ServerHello); err != nil {
			uconn.Close()
			return nil, err
		}
	}
	if st.NegotiatedProtocol == ProtoH2 {
		// Read by the connection only when the server asks to
		// renegotiate, after Dial returns.
		tc.Renegotiation = utls.RenegotiateNever
	}
	return uconn, nil
}

// ecdheAEAD reports whether a TLS 1.2 suite has ECDHE and AEAD.
func ecdheAEAD(suite uint16) bool {
	switch suite {
	case utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return true
	}
	return false
}

// HTTP2Allowed reports whether Chrome sends HTTP/2 over a connection of
// version and suite (SpdySession::HasAcceptableTransportSecurity): TLS
// 1.3, or TLS 1.2 with an AEAD suite without RSA key exchange.
func HTTP2Allowed(version, suite uint16) bool {
	return version >= utls.VersionTLS13 || version == utls.VersionTLS12 && ecdheAEAD(suite)
}

// strictTLS12 checks a TLS 1.2 handshake against StrictTLS12: ECDHE and
// AEAD, extended master secret and secure renegotiation.
func strictTLS12(suite uint16, sh *utls.PubServerHelloMsg) error {
	if !ecdheAEAD(suite) {
		return fmt.Errorf("%w: cipher suite %s", ErrTLS12Policy, utls.CipherSuiteName(suite))
	}
	if sh == nil || !sh.ExtendedMasterSecret {
		return fmt.Errorf("%w: no extended master secret", ErrTLS12Policy)
	}
	if !sh.SecureRenegotiationSupported {
		return fmt.Errorf("%w: no secure renegotiation", ErrTLS12Policy)
	}
	return nil
}

// exactIP returns a VerifyConnection that runs next and then requires an
// IP address SAN with the bytes of ip, as RFC 9525 section 6.4 says and
// Chrome does (X509Certificate::VerifyHostname): crypto/x509 takes an
// IPv4 address and the same address mapped in IPv6 as equal.
func exactIP(ip netip.Addr, next func(utls.ConnectionState) error) func(utls.ConnectionState) error {
	want := ip.AsSlice()
	return func(cs utls.ConnectionState) error {
		if next != nil {
			if err := next(cs); err != nil {
				return err
			}
		}
		if len(cs.PeerCertificates) == 0 {
			return nil
		}
		leaf := cs.PeerCertificates[0]
		for _, a := range leaf.IPAddresses {
			if bytes.Equal(a, want) {
				return nil
			}
		}
		return x509.HostnameError{Certificate: leaf, Host: ip.String()}
	}
}

// Check builds and applies one spec of cfg, as Dial does, without
// connecting, and checks the ClientHello it marshals (checkHello).
// TLS.ServerName may be empty.
func Check(cfg Config) error {
	if cfg.Spec == nil {
		return errors.New("tlsdial: Config.Spec is nil")
	}
	tc := &utls.Config{}
	if cfg.TLS != nil {
		tc = cfg.TLS.Clone()
	}
	if tc.ServerName == "" {
		tc.ServerName = "eidolon.invalid"
	}
	cfg.TLS = tc
	uconn, _, err := prepare(cfg)
	if err != nil {
		return err
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		return fmt.Errorf("%w: %w", ErrProfile, err)
	}
	return checkHello(uconn.HandshakeState.Hello.Raw)
}

// prepare builds a new spec and applies it to a client that has no
// connection yet, and returns the config of the client, which the spec
// changed. Every error wraps ErrProfile.
func prepare(cfg Config) (*utls.UConn, *utls.Config, error) {
	spec, err := cfg.Spec()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}
	if spec == nil {
		return nil, nil, fmt.Errorf("%w: the spec function returned nil", ErrProfile)
	}
	// uTLS copies a name set in the SNI extension into Config.ServerName,
	// which is also the name the certificate is verified against: the spec
	// would choose which certificate is accepted for the URL.
	// RestrictALPN filters ALPN and ALPS only in their own types.
	for _, ext := range spec.Extensions {
		if sni, ok := ext.(*utls.SNIExtension); ok && sni.ServerName != "" {
			return nil, nil, fmt.Errorf("%w: the spec sets the SNI name %q; it must come from the URL", ErrProfile, sni.ServerName)
		}
		if g, ok := ext.(*utls.GenericExtension); ok && (g.Id == extALPN || g.Id == extALPSOld || g.Id == extALPS) {
			return nil, nil, fmt.Errorf("%w: extension %d as a GenericExtension; use the uTLS type of ALPN or ALPS", ErrProfile, g.Id)
		}
	}
	tc := cfg.TLS.Clone()
	uconn := utls.UClient(nil, tc, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}
	return uconn, tc, nil
}
