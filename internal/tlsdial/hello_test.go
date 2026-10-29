package tlsdial

import (
	"errors"
	"slices"
	"strings"
	"testing"

	utls "github.com/acomerlatto/utls"
)

// The signaling cipher suites, of secure renegotiation and of fallback,
// are not refused.
func TestCheckHelloSignalingSuites(t *testing.T) {
	err := Check(Config{Spec: func() (*utls.ClientHelloSpec, error) {
		spec, err := chromeSpec()
		if err == nil {
			spec.CipherSuites = append(spec.CipherSuites, 0x00ff, 0x5600)
		}
		return spec, err
	}})
	if err != nil {
		t.Error(err)
	}
}

// Check refuses a ClientHello the stack cannot honor or that contradicts
// itself, each time with ErrProfile; the Chrome spec passes.
func TestCheckHello(t *testing.T) {
	ext := func(spec *utls.ClientHelloSpec, f func(e utls.TLSExtension)) {
		for _, e := range spec.Extensions {
			f(e)
		}
	}
	for _, tt := range []struct {
		name   string
		change func(spec *utls.ClientHelloSpec)
		want   string
	}{
		{"cipher suite", func(s *utls.ClientHelloSpec) { s.CipherSuites = append(s.CipherSuites, 0xc0ac) }, "cipher suite 0xc0ac"},
		{"extension twice", func(s *utls.ClientHelloSpec) {
			s.Extensions = append(s.Extensions, &utls.ExtendedMasterSecretExtension{})
		}, "extension 23 twice"},
		{"early_data", func(s *utls.ClientHelloSpec) {
			s.Extensions = append(s.Extensions, &utls.GenericExtension{Id: 42})
		}, "early_data"},
		{"pre_shared_key not last", func(s *utls.ClientHelloSpec) {
			s.Extensions = slices.Insert(s.Extensions, 1, utls.TLSExtension(&utls.GenericExtension{Id: 41}))
		}, "pre_shared_key"},
		{"group", func(s *utls.ClientHelloSpec) {
			ext(s, func(e utls.TLSExtension) {
				if g, ok := e.(*utls.SupportedCurvesExtension); ok {
					g.Curves = append(g.Curves, 256)
				}
			})
		}, "supported_groups 0x0100"},
		{"signature scheme", func(s *utls.ClientHelloSpec) {
			ext(s, func(e utls.TLSExtension) {
				if a, ok := e.(*utls.SignatureAlgorithmsExtension); ok {
					a.SupportedSignatureAlgorithms = append(a.SupportedSignatureAlgorithms, 0x0809)
				}
			})
		}, "signature_algorithms 0x0809"},
		{"certificate compression", func(s *utls.ClientHelloSpec) {
			ext(s, func(e utls.TLSExtension) {
				if c, ok := e.(*utls.UtlsCompressCertExtension); ok {
					c.Algorithms = append(c.Algorithms, 4)
				}
			})
		}, "compress_certificate 0x0004"},
		{"key share", func(s *utls.ClientHelloSpec) {
			ext(s, func(e utls.TLSExtension) {
				if k, ok := e.(*utls.KeyShareExtension); ok {
					k.KeyShares = append(k.KeyShares, utls.KeyShare{Group: utls.CurveP521})
				}
			})
		}, "key share of group 25"},
		{"ALPS", func(s *utls.ClientHelloSpec) {
			ext(s, func(e utls.TLSExtension) {
				if a, ok := e.(*utls.ApplicationSettingsExtensionNew); ok {
					a.SupportedProtocols = []string{"h3"}
				}
			})
		}, `ALPS for "h3"`},
		{"two key shares of a group", func(s *utls.ClientHelloSpec) {
			ext(s, func(e utls.TLSExtension) {
				if k, ok := e.(*utls.KeyShareExtension); ok {
					k.KeyShares = append(k.KeyShares, utls.KeyShare{Group: utls.X25519})
				}
			})
		}, "two key shares of group 29"},
		{"pre_shared_key without psk_key_exchange_modes", func(s *utls.ClientHelloSpec) {
			s.Extensions = slices.DeleteFunc(s.Extensions, func(e utls.TLSExtension) bool {
				_, ok := e.(*utls.PSKKeyExchangeModesExtension)
				return ok
			})
			s.Extensions = append(s.Extensions, &utls.GenericExtension{Id: 41})
		}, "pre_shared_key without psk_key_exchange_modes"},
		{"odd supported_versions", func(s *utls.ClientHelloSpec) {
			for i, e := range s.Extensions {
				if _, ok := e.(*utls.SupportedVersionsExtension); ok {
					s.Extensions[i] = &utls.GenericExtension{Id: 43, Data: []byte{1, 3}}
				}
			}
		}, "malformed supported_versions"},
		{"TLS 1.3 without signature_algorithms", func(s *utls.ClientHelloSpec) {
			s.Extensions = slices.DeleteFunc(s.Extensions, func(e utls.TLSExtension) bool {
				_, ok := e.(*utls.SignatureAlgorithmsExtension)
				return ok
			})
		}, "TLS 1.3 without signature_algorithms"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(Config{Spec: func() (*utls.ClientHelloSpec, error) {
				spec, err := chromeSpec()
				if err == nil {
					tt.change(spec)
				}
				return spec, err
			}})
			if !errors.Is(err, ErrProfile) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("%v, want ErrProfile with %q", err, tt.want)
			}
		})
	}
}

// checkHello refuses a ClientHello whose lists are malformed: truncated,
// with bytes after them, empty where the RFCs forbid it, or of an odd
// length for 16-bit values.
func TestCheckHelloMalformed(t *testing.T) {
	// hello is a ClientHello with the cipher suites suites and the
	// extensions exts, each a type and a body.
	hello := func(suites []byte, exts ...[]byte) []byte {
		body := append([]byte{3, 3}, make([]byte, 32)...)
		body = append(body, 0, 0, byte(len(suites)))
		body = append(body, suites...)
		body = append(body, 1, 0)
		var all []byte
		for i := 0; i < len(exts); i += 2 {
			all = append(all, exts[i]...)
			all = append(all, byte(len(exts[i+1])>>8), byte(len(exts[i+1])))
			all = append(all, exts[i+1]...)
		}
		body = append(body, byte(len(all)>>8), byte(len(all)))
		body = append(body, all...)
		return append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	}
	suite := []byte{0x13, 0x01}
	typ := func(t uint16) []byte { return []byte{byte(t >> 8), byte(t)} }
	alpn := []byte{0, 3, 2, 'h', '2'}
	for _, tt := range []struct {
		name string
		msg  []byte
		want string // "" for none
	}{
		{"well formed", hello(suite, typ(extSupportedGroups), []byte{0, 2, 0, 29},
			typ(extKeyShare), []byte{0, 5, 0, 29, 0, 1, 7}, typ(extALPN), alpn,
			typ(extALPS), alpn, typ(extSupportedVersions), []byte{2, 3, 3}), ""},
		{"odd cipher suites", hello([]byte{0x13, 0x01, 0x13}), "malformed cipher suites"},
		{"supported_groups with a trailing byte", hello(suite, typ(extSupportedGroups), []byte{0, 2, 0, 29, 9}), "malformed supported_groups"},
		{"truncated key_share", hello(suite, typ(extSupportedGroups), []byte{0, 2, 0, 29}, typ(extKeyShare), []byte{0, 9, 0, 29}), "malformed key_share"},
		{"empty key_share", hello(suite, typ(extSupportedGroups), []byte{0, 2, 0, 29}, typ(extKeyShare), []byte{}), "malformed key_share"},
		{"key_share with a trailing byte", hello(suite, typ(extSupportedGroups), []byte{0, 2, 0, 29}, typ(extKeyShare), []byte{0, 0, 9}), "malformed key_share"},
		{"truncated ALPN", hello(suite, typ(extALPN), []byte{0, 4, 2, 'h', '2'}), "malformed ALPN"},
		{"ALPN with a trailing byte", hello(suite, typ(extALPN), append(alpn, 9)), "malformed ALPN"},
		{"empty ALPN", hello(suite, typ(extALPN), []byte{0, 0}), "malformed ALPN"},
		{"empty protocol", hello(suite, typ(extALPN), []byte{0, 1, 0}), "malformed ALPN"},
		{"truncated protocol", hello(suite, typ(extALPN), []byte{0, 2, 2, 'h'}), "malformed ALPN"},
		{"truncated ALPS", hello(suite, typ(extALPN), alpn, typ(extALPSOld), []byte{0, 4, 2, 'h', '2'}), "malformed ALPS"},
		{"odd supported_versions", hello(suite, typ(extSupportedVersions), []byte{1, 3}), "malformed supported_versions"},
		{"truncated supported_versions", hello(suite, typ(extSupportedVersions), []byte{4, 3, 4}), "malformed supported_versions"},
		{"supported_versions with a trailing byte", hello(suite, typ(extSupportedVersions), []byte{2, 3, 4, 9}), "malformed supported_versions"},
		{"empty supported_versions", hello(suite, typ(extSupportedVersions), []byte{0}), "malformed supported_versions"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := checkHello(tt.msg)
			if tt.want == "" && err != nil || tt.want != "" && (!errors.Is(err, ErrProfile) || !strings.Contains(err.Error(), tt.want)) {
				t.Errorf("%v, want %q", err, tt.want)
			}
		})
	}
}
