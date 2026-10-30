package eidolon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	utls "github.com/acomerlatto/utls"
	"github.com/acomerlatto/utls/dicttls"

	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// ClientHelloOption is an option of ClientHelloFromRaw.
type ClientHelloOption func(*clientHelloConfig)

type clientHelloConfig struct {
	shuffle bool
}

// WithShuffledExtensions shuffles the extensions of each ClientHello as
// Chrome does since version 106 (utls.ShuffleChromeTLSExtensions): GREASE,
// padding and pre_shared_key keep their places.
func WithShuffledExtensions() ClientHelloOption {
	return func(c *clientHelloConfig) { c.shuffle = true }
}

// ClientHelloFromRaw returns a ClientHello function, for WithClientHello or
// Profile.ClientHello, that rebuilds a captured ClientHello for each
// connection: raw is the ClientHello handshake message, with or without
// its TLS record header. Each connection has new GREASE values, random,
// session ID and key shares; uTLS leaves the captured server name out of
// SNI, and the one sent is the host of the URL. The extensions keep the captured order
// unless WithShuffledExtensions is given. A captured pre_shared_key is
// left out, or carries a session of the client when it resumes one;
// without it, pre_shared_key is added at the end when the ClientHello
// offers psk_key_exchange_modes, as Chrome does. A GREASE
// encrypted_client_hello of BoringSSL draws its payload length again, as
// Chrome; another keeps the captured one.
//
// The ClientHello is checked once, as New checks every spec: an extension
// uTLS does not know, an extension twice, a malformed list, pre_shared_key
// other than last or without psk_key_exchange_modes, a cipher suite, group,
// signature scheme or certificate compression the stack does not
// implement, a capability it cannot honor (such as early_data), a key
// share outside supported_groups or two of one group, ALPS for a protocol
// ALPN does not offer, or TLS 1.3 without key_share, supported_groups or
// signature_algorithms return an error that wraps ErrProfile, and a nil
// option one that wraps ErrConfig. raw is copied.
func ClientHelloFromRaw(raw []byte, opts ...ClientHelloOption) (func() (*utls.ClientHelloSpec, error), error) {
	var cfg clientHelloConfig
	for _, o := range opts {
		if o == nil {
			return nil, fmt.Errorf("ClientHelloFromRaw: %w: nil option", ErrConfig)
		}
		o(&cfg)
	}
	record, err := clientHelloRecord(raw)
	if err != nil {
		return nil, fmt.Errorf("ClientHelloFromRaw: %w: %w", ErrProfile, err)
	}
	spec := func() (*utls.ClientHelloSpec, error) {
		// pre_shared_key resumes a session of the client, not the
		// captured one.
		spec, err := (&utls.Fingerprinter{RealPSKResumption: true}).FingerprintClientHello(record)
		if err != nil {
			return nil, err
		}
		boringGREASEECH(spec.Extensions)
		if cfg.shuffle {
			spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
		}
		return spec, nil
	}
	if err := tlsdial.Check(tlsdial.Config{Spec: spec}); err != nil {
		return nil, fmt.Errorf("ClientHelloFromRaw: %w", err)
	}
	return spec, nil
}

// boringGREASEECH makes a GREASE encrypted_client_hello of exts in the
// shape BoringSSL gives it (setup_ech_grease) draw its payload length
// among BoringSSL's, where uTLS keeps the captured one: HKDF-SHA256,
// AES-128-GCM or ChaCha20-Poly1305, an X25519 enc, and 128 to 224 bytes
// in steps of 32 before the AEAD overhead.
func boringGREASEECH(exts []utls.TLSExtension) {
	boring := utls.BoringGREASEECH().CandidatePayloadLens
	for _, e := range exts {
		g, ok := e.(*utls.GREASEEncryptedClientHelloExtension)
		// Write sets one cipher suite and one length, those captured.
		if !ok || len(g.EncapsulatedKey) != 32 || !slices.Contains(boring, g.CandidatePayloadLens[0]) {
			continue
		}
		if cs := g.CandidateCipherSuites[0]; cs.KdfId == dicttls.HKDF_SHA256 &&
			(cs.AeadId == dicttls.AEAD_AES_128_GCM || cs.AeadId == dicttls.AEAD_CHACHA20_POLY1305) {
			g.CandidatePayloadLens = boring
		}
	}
}

// clientHelloRecord returns a copy of raw in a TLS record, adding the
// header when raw is the handshake message alone. uTLS checks the rest.
func clientHelloRecord(raw []byte) ([]byte, error) {
	if len(raw) > 0 && raw[0] == 1 { // handshake type client_hello
		if len(raw) > 1<<16-1 {
			return nil, errors.New("ClientHello too long for a record")
		}
		return append(binary.BigEndian.AppendUint16([]byte{22, 3, 1}, uint16(len(raw))), raw...), nil
	}
	return append([]byte(nil), raw...), nil
}
