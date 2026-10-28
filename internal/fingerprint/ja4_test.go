package fingerprint

import (
	"os"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// hello marshals a ClientHello handshake message with legacy_version
// version, the cipher suites and the extensions.
func hello(version uint16, suites []uint16, exts ...Extension) []byte {
	var b cryptobyte.Builder
	b.AddUint8(1)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(version)
		b.AddBytes(make([]byte, 32))
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte{1, 2}) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, s := range suites {
				b.AddUint16(s)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
		if exts == nil {
			return
		}
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, e := range exts {
				b.AddUint16(e.Type)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.Data) })
			}
		})
	})
	return b.BytesOrPanic()
}

// ext returns an extension whose body is a list of 16-bit values with a
// length of lenBytes.
func ext(typ uint16, lenBytes int, values ...uint16) Extension {
	var b cryptobyte.Builder
	add := func(b *cryptobyte.Builder) {
		for _, v := range values {
			b.AddUint16(v)
		}
	}
	if lenBytes == 1 {
		b.AddUint8LengthPrefixed(add)
	} else {
		b.AddUint16LengthPrefixed(add)
	}
	return Extension{typ, b.BytesOrPanic()}
}

// alpn returns an ALPN extension offering protos.
func alpn(protos ...string) Extension {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, p := range protos {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(p)) })
		}
	})
	return Extension{extALPN, b.BytesOrPanic()}
}

func parse(t *testing.T, msg []byte) *ClientHello {
	t.Helper()
	h, err := ParseClientHello(msg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The Chrome example of the JA4 README of FoxIO, with GREASE added.
func TestJA4FoxIO(t *testing.T) {
	suites := []uint16{0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	exts := []Extension{
		{0x2a2a, nil},
		{0x0000, []byte{0, 14, 0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}},
		{0x0017, nil},
		{0xff01, []byte{0}},
		ext(0x000a, 2, 0x3a3a, 0x001d, 0x0017, 0x0018),
		{0x000b, []byte{1, 0}},
		{0x0023, nil},
		alpn("h2", "http/1.1"),
		{0x0005, []byte{1, 0, 0, 0, 0}},
		ext(0x000d, 2, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601),
		{0x0012, nil},
		{0x0033, nil},
		{0x002d, []byte{1, 1}},
		ext(0x002b, 1, 0x4a4a, 0x0304, 0x0303),
		{0x001b, []byte{2, 0, 2}},
		{0x4469, nil},
		{0x5a5a, []byte{0}},
		{0x0015, make([]byte, 20)},
	}
	if got, want := parse(t, hello(0x0303, suites, exts...)).JA4(), "t13d1516h2_8daaf6152771_e5627efa2ab1"; got != want {
		t.Errorf("JA4 = %s, want %s", got, want)
	}
}

// The ClientHello Chrome 156 sent to the lab; the value was computed
// apart, with Python.
func TestJA4Chrome156(t *testing.T) {
	b, err := os.ReadFile("../../testdata/chrome156-linux-clienthello.bin")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := parse(t, b[5:]).JA4(), "t13d1517h2_8daaf6152771_cb7bf5808d99"; got != want {
		t.Errorf("JA4 = %s, want %s", got, want)
	}
}

func TestJA4Raw(t *testing.T) {
	for _, tt := range []struct {
		name    string
		msg     []byte
		a, b, c string
	}{
		{"TLS 1.2 bare", hello(0x0303, []uint16{0x1301}, Extension{0x0017, nil}), "t12i010100", "1301", "0017"},
		{"no extensions", hello(0x0303, nil), "t12i000000", "", ""},
		{"SSL 3", hello(0x0300, nil), "ts3i000000", "", ""},
		{"TLS 1.1", hello(0x0302, nil), "t11i000000", "", ""},
		{"TLS 1.0", hello(0x0301, nil), "t10i000000", "", ""},
		{"unknown version", hello(0x0100, nil), "t00i000000", "", ""},
		{"supported_versions", hello(0x0303, nil, ext(0x002b, 1, 0x0302, 0x0304, 0x0303, 0xfafa)), "t13i000100", "", "002b"},
		{"supported_versions GREASE only", hello(0x0303, nil, ext(0x002b, 1, 0xfafa)), "t00i000100", "", "002b"},
		{"suites sorted", hello(0x0303, []uint16{0xc02b, 0x0a0a, 0x1301}), "t12i020000", "1301,c02b", ""},
		{"ALPN not alphanumeric", hello(0x0303, nil, alpn("\x01h")), "t12i000108", "", ""},
		{"ALPN last not alphanumeric", hello(0x0303, nil, alpn("h/")), "t12i00016f", "", ""},
		{"ALPN of one character", hello(0x0303, nil, alpn("x")), "t12i0001xx", "", ""},
		{"ALPN upper case", hello(0x0303, nil, alpn("Ab")), "t12i0001Ab", "", ""},
		{"ALPN empty protocol", hello(0x0303, nil, alpn("")), "t12i000100", "", ""},
		{"ALPN empty list", hello(0x0303, nil, Extension{extALPN, []byte{0, 0}}), "t12i000100", "", ""},
		{"sigalgs", hello(0x0303, nil, ext(0x000d, 2, 0x0804, 0x1a1a, 0x0403), Extension{0x0000, nil}),
			"t12d000200", "", "000d_0804,0403"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, b, c := parse(t, tt.msg).ja4Raw()
			if a != tt.a || b != tt.b || c != tt.c {
				t.Errorf("JA4 raw = %q %q %q, want %q %q %q", a, b, c, tt.a, tt.b, tt.c)
			}
		})
	}
}

// Counts stop at 99.
func TestJA4Counts(t *testing.T) {
	var suites []uint16
	var exts []Extension
	for i := range 100 {
		suites = append(suites, 0xc000+uint16(i))
		exts = append(exts, Extension{0xe000 + uint16(i), nil})
	}
	if a, _, _ := parse(t, hello(0x0303, suites, exts...)).ja4Raw(); a != "t12i999900" {
		t.Errorf("JA4 a = %s", a)
	}
}

func TestIsGREASE(t *testing.T) {
	for v, want := range map[uint16]bool{0x0a0a: true, 0xfafa: true, 0x1a1a: true, 0x1a0a: false, 0x0a1a: false, 0x0b0b: false, 0x1301: false} {
		if IsGREASE(v) != want {
			t.Errorf("IsGREASE(%#04x) = %v", v, !want)
		}
	}
}

func TestJA4Hash(t *testing.T) {
	if got := ja4Hash(""); got != "000000000000" {
		t.Errorf("empty: %s", got)
	}
	if got := ja4Hash("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"); got != "8daaf6152771" {
		t.Errorf("Chrome cipher suites: %s", got)
	}
}

func TestParseClientHello(t *testing.T) {
	h := parse(t, hello(0x0303, []uint16{0x1301, 0x1302}, Extension{0x0017, nil}, Extension{0x0000, []byte{1}}))
	if h.Version != 0x0303 || string(h.SessionID) != "\x01\x02" || len(h.CipherSuites) != 2 || h.CipherSuites[1] != 0x1302 ||
		string(h.Compression) != "\x00" || len(h.Extensions) != 2 || h.Extensions[1].Type != 0 || string(h.Extensions[1].Data) != "\x01" {
		t.Errorf("parsed %+v", h)
	}
	if d, ok := h.Extension(0x0017); !ok || len(d) != 0 {
		t.Error("extension 0x17 missing")
	}
	if _, ok := h.Extension(0x0010); ok {
		t.Error("extension 0x10 found")
	}
	// head is legacy_version, random and an empty session ID.
	head := slices.Clip(append([]byte{3, 3}, make([]byte, 33)...))
	raw := func(body []byte) []byte {
		var b cryptobyte.Builder
		b.AddUint8(1)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body) })
		return b.BytesOrPanic()
	}
	if _, err := ParseClientHello(raw(append(head, 0, 2, 0x13, 1, 1, 0, 0, 0))); err != nil {
		t.Errorf("raw: %v", err)
	}
	good := hello(0x0303, []uint16{0x1301}, Extension{0x0017, nil})
	for name, msg := range map[string][]byte{
		"empty":             nil,
		"not a ClientHello": append([]byte{2}, good[1:]...),
		"trailing byte":     append(append([]byte(nil), good...), 0),
		"truncated":         good[:len(good)-1],
		"odd suites":        raw(append(head, 0, 1, 0x13, 1, 0)),
		"bad extension":     raw(append(head, 0, 2, 0x13, 1, 1, 0, 0, 3, 0, 1, 0)),
		"after extensions":  raw(append(head, 0, 2, 0x13, 1, 1, 0, 0, 0, 0)),
	} {
		if _, err := ParseClientHello(msg); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
