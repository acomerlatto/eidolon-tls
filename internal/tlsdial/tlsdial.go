// Package tlsdial opens TLS connections with a uTLS ClientHello spec.
//
// Dial owns the connection until it returns it: on any error the TCP
// connection is closed, so no HTTP byte can be written on a connection that
// failed TLS or ALPN.
package tlsdial

import (
	"context"
	"errors"
	"fmt"
	"net"

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
}

// Dial opens a TCP connection to addr, performs the TLS handshake with a new
// spec and checks the negotiated ALPN protocol. The returned connection has
// completed the handshake; its protocol is ConnectionState().NegotiatedProtocol.
func Dial(ctx context.Context, network, addr string, cfg Config) (*utls.UConn, error) {
	if cfg.Spec == nil {
		return nil, errors.New("tlsdial: Config.Spec is nil")
	}
	if cfg.TLS == nil || cfg.TLS.ServerName == "" {
		return nil, errors.New("tlsdial: Config.TLS.ServerName is empty")
	}
	// Build the spec before dialing, so a spec error opens no connection.
	spec, err := cfg.Spec()
	if err != nil {
		return nil, fmt.Errorf("tlsdial: ClientHello spec: %w", err)
	}
	if spec == nil {
		return nil, errors.New("tlsdial: ClientHello spec is nil")
	}
	// uTLS copies a name set in the SNI extension into Config.ServerName,
	// which is also the name the certificate is verified against: the spec
	// would choose which certificate is accepted for the URL.
	for _, ext := range spec.Extensions {
		if sni, ok := ext.(*utls.SNIExtension); ok && sni.ServerName != "" {
			return nil, fmt.Errorf("tlsdial: ClientHello spec sets the SNI name %q; it must come from the URL", sni.ServerName)
		}
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

	uconn := utls.UClient(conn, cfg.TLS.Clone(), utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tlsdial: apply ClientHello spec: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		var ve *utls.CertificateVerificationError
		if errors.As(err, &ve) {
			err = fmt.Errorf("%w: %w", ErrCertificate, err)
		}
		return nil, err
	}
	switch proto := uconn.ConnectionState().NegotiatedProtocol; proto {
	case ProtoH2, ProtoHTTP1, "":
		return uconn, nil
	default:
		uconn.Close()
		return nil, fmt.Errorf("%w: %q", ErrALPN, proto)
	}
}
