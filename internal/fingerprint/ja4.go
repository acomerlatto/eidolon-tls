// Package fingerprint reads a ClientHello and computes its JA4
// fingerprint, which the tests compare with a capture.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// Extension types JA4 reads.
const (
	extServerName        = 0
	extSignatureAlgs     = 13
	extALPN              = 16
	extSupportedVersions = 43
)

// Extension is a ClientHello extension, with its body.
type Extension struct {
	Type uint16
	Data []byte
}

// ClientHello is a parsed ClientHello handshake message.
type ClientHello struct {
	Version      uint16 // legacy_version
	SessionID    []byte
	CipherSuites []uint16
	Compression  []byte
	Extensions   []Extension
}

// IsGREASE reports whether v is a GREASE value (RFC 8701).
func IsGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// ParseClientHello parses msg, a ClientHello handshake message without
// its record header.
func ParseClientHello(msg []byte) (*ClientHello, error) {
	s := cryptobyte.String(msg)
	var typ uint8
	var body, sessionID, suites, compression, exts cryptobyte.String
	h := &ClientHello{}
	if !s.ReadUint8(&typ) || typ != 1 || !s.ReadUint24LengthPrefixed(&body) || !s.Empty() ||
		!body.ReadUint16(&h.Version) || !body.Skip(32) ||
		!body.ReadUint8LengthPrefixed(&sessionID) || !body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8LengthPrefixed(&compression) {
		return nil, errors.New("malformed ClientHello")
	}
	h.SessionID, h.Compression = sessionID, compression
	for !suites.Empty() {
		var v uint16
		if !suites.ReadUint16(&v) {
			return nil, errors.New("malformed cipher suites")
		}
		h.CipherSuites = append(h.CipherSuites, v)
	}
	if body.Empty() {
		return h, nil
	}
	if !body.ReadUint16LengthPrefixed(&exts) || !body.Empty() {
		return nil, errors.New("malformed extensions")
	}
	for !exts.Empty() {
		var e Extension
		var data cryptobyte.String
		if !exts.ReadUint16(&e.Type) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, errors.New("malformed extensions")
		}
		e.Data = data
		h.Extensions = append(h.Extensions, e)
	}
	return h, nil
}

// Extension returns the body of the extension typ, and whether h has it.
func (h *ClientHello) Extension(typ uint16) ([]byte, bool) {
	for _, e := range h.Extensions {
		if e.Type == typ {
			return e.Data, true
		}
	}
	return nil, false
}

// JA4 returns the JA4 fingerprint of h over TCP, as FoxIO specifies it:
// a_b_c, where a is "t", the TLS version, "d" with SNI or "i" without, the
// number of cipher suites and of extensions and the first and last
// characters of the first ALPN protocol; b is the truncated SHA-256 of the
// sorted cipher suites; c that of the sorted extensions but SNI and ALPN,
// then the signature algorithms in their order. GREASE values are left
// out.
func (h *ClientHello) JA4() string {
	a, b, c := h.ja4Raw()
	return a + "_" + ja4Hash(b) + "_" + ja4Hash(c)
}

// ja4Raw returns the parts of JA4 before b and c are hashed.
func (h *ClientHello) ja4Raw() (a, b, c string) {
	var suites, exts, others, sigs []string
	for _, v := range h.CipherSuites {
		if !IsGREASE(v) {
			suites = append(suites, fmt.Sprintf("%04x", v))
		}
	}
	for _, e := range h.Extensions {
		if IsGREASE(e.Type) {
			continue
		}
		exts = append(exts, fmt.Sprintf("%04x", e.Type))
		if e.Type != extServerName && e.Type != extALPN {
			others = append(others, fmt.Sprintf("%04x", e.Type))
		}
	}
	if data, ok := h.Extension(extSignatureAlgs); ok {
		for _, v := range list16(data, 2) {
			if !IsGREASE(v) {
				sigs = append(sigs, fmt.Sprintf("%04x", v))
			}
		}
	}
	sni := "i"
	if _, ok := h.Extension(extServerName); ok {
		sni = "d"
	}
	a = fmt.Sprintf("t%s%s%02d%02d%s", h.ja4Version(), sni, min(len(suites), 99), min(len(exts), 99), h.ja4ALPN())
	slices.Sort(suites)
	slices.Sort(others)
	c = strings.Join(others, ",")
	if len(sigs) > 0 {
		c += "_" + strings.Join(sigs, ",")
	}
	return a, strings.Join(suites, ","), c
}

// ja4Version returns the highest version of supported_versions, or else
// legacy_version, as JA4 writes it.
func (h *ClientHello) ja4Version() string {
	v := h.Version
	if data, ok := h.Extension(extSupportedVersions); ok {
		v = 0
		for _, sv := range list16(data, 1) {
			if !IsGREASE(sv) && sv > v {
				v = sv
			}
		}
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	}
	return "00"
}

// ja4ALPN returns the first and last characters of the first ALPN
// protocol, the first and last hex digits of it when either is not
// alphanumeric, or "00" without ALPN.
func (h *ClientHello) ja4ALPN() string {
	data, _ := h.Extension(extALPN)
	s := cryptobyte.String(data)
	var list, p cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) || !list.ReadUint8LengthPrefixed(&p) || len(p) == 0 {
		return "00"
	}
	first, last := p[0], p[len(p)-1]
	if !alnum(first) || !alnum(last) {
		x := hex.EncodeToString(p)
		return x[:1] + x[len(x)-1:]
	}
	return string([]byte{first, last})
}

func alnum(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// ja4Hash returns the first 12 hex digits of the SHA-256 of s, or 12
// zeros for an empty s.
func ja4Hash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// list16 reads a list of 16-bit values whose length takes lenBytes.
func list16(data []byte, lenBytes int) []uint16 {
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if lenBytes == 1 && !s.ReadUint8LengthPrefixed(&list) || lenBytes == 2 && !s.ReadUint16LengthPrefixed(&list) {
		return nil
	}
	var out []uint16
	for v := uint16(0); list.ReadUint16(&v); {
		out = append(out, v)
	}
	return out
}
