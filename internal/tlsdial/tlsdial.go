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
	"slices"

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

// ErrECHRejected reports a server that rejected ECH. The
// utls.ECHRejectionError, with the retry configurations of an
// authenticated rejection, stays in the chain. No HTTP byte is sent.
var ErrECHRejected = errors.New("eidolon: the server rejected ECH")

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

	// Sessions, when set, returns the session cache of each new
	// connection: the connection resumes a session from it and keeps
	// there the ones the server sends.
	Sessions func() Sessions
}

// Sessions is the session cache of one connection. Get and Put are
// called during the handshake and, in TLS 1.3, Put after it.
type Sessions interface {
	utls.ClientSessionCache
	// Unused gives back the session Get returned to a connection whose
	// TCP dial failed: it was never sent.
	Unused()
	// Handshake reports the end of the handshake, its TLS version, and
	// whether it resumed the session Get returned. It comes before the
	// Put calls after the handshake.
	Handshake(version uint16, resumed bool)
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
	var sessions Sessions
	if cfg.Sessions != nil {
		sessions = cfg.Sessions()
	}
	// Build the ClientHello before dialing, so a bad profile opens no
	// connection.
	uconn, tc, err := prepare(cfg, sessions)
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
		if sessions != nil {
			sessions.Unused()
		}
		return nil, err
	}
	uconn.SetUnderlyingConn(conn)
	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		var ve *utls.CertificateVerificationError
		var he x509.HostnameError
		var re *utls.ECHRejectionError
		switch {
		case errors.As(err, &ve) || errors.As(err, &he):
			err = fmt.Errorf("%w: %w", ErrCertificate, err)
		case errors.As(err, &re):
			err = fmt.Errorf("%w: %w", ErrECHRejected, err)
		}
		return nil, err
	}
	st := uconn.ConnectionState()
	if sessions != nil {
		sessions.Handshake(st.Version, st.DidResume)
	}
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
	_, _, err := prepare(cfg, nil)
	return err
}

// prepare builds a new spec, applies it to a client that has no
// connection yet and builds its ClientHello, checked by checkHello and,
// with ECH, for TLS 1.3 and server_name, and
// returns the config of the client, which the spec changed. With
// sessions, the ClientHello resumes a session from it: a spec that offers
// psk_key_exchange_modes without pre_shared_key gets one, last, as
// Chrome adds it to a ClientHello that resumes. Every error wraps
// ErrProfile.
func prepare(cfg Config, sessions Sessions) (*utls.UConn, *utls.Config, error) {
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
	// An extension uTLS has a type for, written as a GenericExtension, is
	// sent as given while uTLS keeps none of its state: a server name
	// other than the verified one, ALPN and ALPS out of RestrictALPN's
	// reach, versions or key shares the handshake does not know.
	var hasSNI bool
	for _, ext := range spec.Extensions {
		if sni, ok := ext.(*utls.SNIExtension); ok {
			if sni.ServerName != "" {
				return nil, nil, fmt.Errorf("%w: the spec sets the SNI name %q; it must come from the URL", ErrProfile, sni.ServerName)
			}
			hasSNI = true
		}
		if g, ok := ext.(*utls.GenericExtension); ok && !isGREASE(g.Id) && utls.ExtensionFromID(g.Id) != nil {
			return nil, nil, fmt.Errorf("%w: extension %d as a GenericExtension; use its uTLS type", ErrProfile, g.Id)
		}
	}
	tc := cfg.TLS.Clone()
	// Without a session, pre_shared_key is left out, as Chrome does. A
	// spec without pre_shared_key, or without session_ticket, does not
	// resume the sessions it would carry (TLS 1.3, TLS 1.2).
	tc.OmitEmptyPsk = true
	tc.PreferSkipResumptionOnNilExtension = true
	if sessions != nil {
		tc.ClientSessionCache = sessions
		addPSK(spec)
	}
	uconn := utls.UClient(nil, tc, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}
	if err := checkHello(uconn.HandshakeState.Hello.Raw); err != nil {
		return nil, nil, err
	}
	// ClientHelloInner takes the versions and server_name of the outer:
	// without TLS 1.3 no server accepts ECH, and without server_name
	// ClientHelloInner names no server.
	if len(tc.EncryptedClientHelloConfigList) > 0 &&
		(!slices.Contains(uconn.HandshakeState.Hello.SupportedVersions, utls.VersionTLS13) || !hasSNI) {
		return nil, nil, fmt.Errorf("%w: ECH needs a profile that offers TLS 1.3 and server_name", ErrProfile)
	}
	return uconn, tc, nil
}

// addPSK adds pre_shared_key, last, to a spec that offers
// psk_key_exchange_modes without it.
func addPSK(spec *utls.ClientHelloSpec) {
	modes := false
	for _, ext := range spec.Extensions {
		switch ext.(type) {
		case utls.PreSharedKeyExtension:
			return
		case *utls.PSKKeyExchangeModesExtension:
			modes = true
		}
	}
	if modes {
		spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
	}
}
