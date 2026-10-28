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
