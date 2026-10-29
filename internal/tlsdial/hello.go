package tlsdial

import (
	"fmt"
	"slices"

	utls "github.com/acomerlatto/utls"
	"golang.org/x/crypto/cryptobyte"
)

// Extension types that checkHello reads.
const (
	extSupportedGroups   = 10
	extSignatureAlgs     = 13
	extALPN              = 16
	extCompressCert      = 27
	extPreSharedKey      = 41
	extSupportedVersions = 43
	extPSKModes          = 45
	extKeyShare          = 51
	extALPSOld           = 17513
	extALPS              = 17613
)

// refusedExtensions are capabilities a ClientHello may not announce, as
// the stack cannot honor them if the server takes them up.
var refusedExtensions = map[uint16]string{
	1:  "max_fragment_length",
	22: "encrypt_then_mac",
	42: "early_data",
	49: "post_handshake_auth",
}

// implementedGroups are the groups uTLS makes key shares for.
var implementedGroups = []uint16{
	uint16(utls.X25519), uint16(utls.CurveP256), uint16(utls.CurveP384), uint16(utls.CurveP521),
	uint16(utls.X25519MLKEM768), uint16(utls.SecP256r1MLKEM768), uint16(utls.SecP384r1MLKEM1024),
	uint16(utls.X25519Kyber768Draft00),
}

// implementedSignatures are the signature schemes the stack verifies.
var implementedSignatures = []uint16{
	uint16(utls.PKCS1WithSHA256), uint16(utls.PKCS1WithSHA384), uint16(utls.PKCS1WithSHA512),
	uint16(utls.PSSWithSHA256), uint16(utls.PSSWithSHA384), uint16(utls.PSSWithSHA512),
	uint16(utls.ECDSAWithP256AndSHA256), uint16(utls.ECDSAWithP384AndSHA384), uint16(utls.ECDSAWithP521AndSHA512),
	uint16(utls.Ed25519), uint16(utls.PKCS1WithSHA1), uint16(utls.ECDSAWithSHA1),
	uint16(utls.MLDSA44), uint16(utls.MLDSA65), uint16(utls.MLDSA87),
}

// implementedCertCompression are the certificate compression algorithms
// uTLS decompresses: zlib, brotli and zstd.
var implementedCertCompression = []uint16{1, 2, 3}

// isGREASE reports whether v is a GREASE value (RFC 8701).
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// implementedSuite reports whether the stack negotiates suite, or it is a
// signaling value.
func implementedSuite(suite uint16) bool {
	if suite == 0x00ff || suite == 0x5600 { // renegotiation and fallback SCSV
		return true
	}
	for _, s := range append(utls.CipherSuites(), utls.InsecureCipherSuites()...) {
		if s.ID == suite {
			return true
		}
	}
	return false
}

// checkHello checks a marshalled ClientHello handshake message: the lists
// it reads well formed, no extension twice, pre_shared_key last and with
// psk_key_exchange_modes, no capability the stack cannot honor (cipher
// suites, groups, signature schemes, certificate compression,
// refusedExtensions), key shares among the supported groups and one per
// group, ALPS only for protocols ALPN offers, and with TLS 1.3 the
// extensions it needs. Every error wraps ErrProfile.
func checkHello(msg []byte) error {
	s := cryptobyte.String(msg)
	var suites, compression, exts cryptobyte.String
	if !s.Skip(4+2+32) || !s.Skip(1+int(peek(s))) ||
		!s.ReadUint16LengthPrefixed(&suites) || !s.ReadUint8LengthPrefixed(&compression) ||
		!s.ReadUint16LengthPrefixed(&exts) {
		return fmt.Errorf("%w: malformed ClientHello", ErrProfile)
	}
	for !suites.Empty() {
		var suite uint16
		if !suites.ReadUint16(&suite) {
			return fmt.Errorf("%w: malformed cipher suites", ErrProfile)
		}
		if !isGREASE(suite) && !implementedSuite(suite) {
			return fmt.Errorf("%w: cipher suite %#04x is not implemented", ErrProfile, suite)
		}
	}
	data := map[uint16]cryptobyte.String{}
	for !exts.Empty() {
		var typ uint16
		var body cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&body) {
			return fmt.Errorf("%w: malformed extensions", ErrProfile)
		}
		if _, dup := data[typ]; dup {
			return fmt.Errorf("%w: extension %d twice", ErrProfile, typ)
		}
		if name, ok := refusedExtensions[typ]; ok {
			return fmt.Errorf("%w: extension %s is not implemented", ErrProfile, name)
		}
		if _, ok := data[extPreSharedKey]; ok {
			return fmt.Errorf("%w: pre_shared_key is not the last extension", ErrProfile)
		}
		data[typ] = body
	}
	if _, ok := data[extPreSharedKey]; ok {
		if _, ok := data[extPSKModes]; !ok {
			return fmt.Errorf("%w: pre_shared_key without psk_key_exchange_modes", ErrProfile)
		}
	}
	groups, err := list16(data, extSupportedGroups, 2, "supported_groups", implementedGroups)
	if err != nil {
		return err
	}
	if _, err := list16(data, extSignatureAlgs, 2, "signature_algorithms", implementedSignatures); err != nil {
		return err
	}
	if _, err := list16(data, extCompressCert, 1, "compress_certificate", implementedCertCompression); err != nil {
		return err
	}
	if ks, ok := data[extKeyShare]; ok {
		var shares cryptobyte.String
		if !ks.ReadUint16LengthPrefixed(&shares) || !ks.Empty() {
			return fmt.Errorf("%w: malformed key_share", ErrProfile)
		}
		var seen []uint16
		for !shares.Empty() {
			var group uint16
			var key cryptobyte.String
			if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&key) {
				return fmt.Errorf("%w: malformed key_share", ErrProfile)
			}
			if !slices.Contains(groups, group) {
				return fmt.Errorf("%w: key share of group %d, not in supported_groups", ErrProfile, group)
			}
			if slices.Contains(seen, group) {
				return fmt.Errorf("%w: two key shares of group %d", ErrProfile, group)
			}
			seen = append(seen, group)
		}
	}
	alpn, err := protocols(data, extALPN, "ALPN")
	if err != nil {
		return err
	}
	for _, typ := range []uint16{extALPSOld, extALPS} {
		alps, err := protocols(data, typ, "ALPS")
		if err != nil {
			return err
		}
		for _, p := range alps {
			if !slices.Contains(alpn, p) {
				return fmt.Errorf("%w: ALPS for %q, which ALPN does not offer", ErrProfile, p)
			}
		}
	}
	if versions, ok := data[extSupportedVersions]; ok {
		var list cryptobyte.String
		if !versions.ReadUint8LengthPrefixed(&list) || !versions.Empty() || list.Empty() {
			return fmt.Errorf("%w: malformed supported_versions", ErrProfile)
		}
		for !list.Empty() {
			var v uint16
			if !list.ReadUint16(&v) {
				return fmt.Errorf("%w: malformed supported_versions", ErrProfile)
			}
			if v != utls.VersionTLS13 {
				continue
			}
			for typ, name := range map[uint16]string{extKeyShare: "key_share", extSupportedGroups: "supported_groups", extSignatureAlgs: "signature_algorithms"} {
				if _, ok := data[typ]; !ok {
					return fmt.Errorf("%w: TLS 1.3 without %s", ErrProfile, name)
				}
			}
		}
	}
	return nil
}

// peek returns the first byte of s, or 0.
func peek(s cryptobyte.String) byte {
	if len(s) == 0 {
		return 0
	}
	return s[0]
}

// list16 reads the list of 16-bit values of extension typ, whose length
// takes lenBytes, and checks that each one but GREASE is in implemented.
func list16(data map[uint16]cryptobyte.String, typ uint16, lenBytes int, name string, implemented []uint16) ([]uint16, error) {
	body, ok := data[typ]
	if !ok {
		return nil, nil
	}
	var list cryptobyte.String
	if lenBytes == 1 && !body.ReadUint8LengthPrefixed(&list) || lenBytes == 2 && !body.ReadUint16LengthPrefixed(&list) || !body.Empty() {
		return nil, fmt.Errorf("%w: malformed %s", ErrProfile, name)
	}
	var out []uint16
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return nil, fmt.Errorf("%w: malformed %s", ErrProfile, name)
		}
		if !isGREASE(v) && !slices.Contains(implemented, v) {
			return nil, fmt.Errorf("%w: %s %#04x is not implemented", ErrProfile, name, v)
		}
		out = append(out, v)
	}
	return out, nil
}

// protocols reads the protocol list of extension typ, ALPN or ALPS, nil
// without it: a non-empty list of non-empty names (RFC 7301 section 3.1).
func protocols(data map[uint16]cryptobyte.String, typ uint16, name string) ([]string, error) {
	body, ok := data[typ]
	if !ok {
		return nil, nil
	}
	var list cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&list) || !body.Empty() || list.Empty() {
		return nil, fmt.Errorf("%w: malformed %s", ErrProfile, name)
	}
	var out []string
	for !list.Empty() {
		var p cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&p) || p.Empty() {
			return nil, fmt.Errorf("%w: malformed %s", ErrProfile, name)
		}
		out = append(out, string(p))
	}
	return out, nil
}
