package tlsdial

import (
	"errors"
	"slices"
	"testing"

	utls "github.com/acomerlatto/utls"
)

// alpnOf returns the ALPN protocols and the ALPS protocols of spec, nil
// when the extension is absent.
func alpnOf(spec *utls.ClientHelloSpec) (alpn, alps []string) {
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			alpn = e.AlpnProtocols
		case *utls.ApplicationSettingsExtension:
			alps = e.SupportedProtocols
		case *utls.ApplicationSettingsExtensionNew:
			alps = e.SupportedProtocols
		}
	}
	return alpn, alps
}

func TestRestrictALPN(t *testing.T) {
	tests := []struct {
		name               string
		protos             []string
		wantALPN, wantALPS []string
	}{
		// Chromium registers ALPS by walking the ALPN list: with only
		// http/1.1 offered, the extension is left out.
		{"HTTP/1.1 only", []string{ProtoHTTP1}, []string{ProtoHTTP1}, nil},
		{"h2 only", []string{ProtoH2}, []string{ProtoH2}, []string{ProtoH2}},
		// The spec's order is kept, not the order of protos.
		{"both", []string{ProtoHTTP1, ProtoH2}, []string{ProtoH2, ProtoHTTP1}, []string{ProtoH2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := chromeSpec()
			if err != nil {
				t.Fatal(err)
			}
			before := slices.Clone(spec.Extensions)
			origALPN, origALPS := alpnOf(&utls.ClientHelloSpec{Extensions: before})
			origALPN, origALPS = slices.Clone(origALPN), slices.Clone(origALPS)

			restricted := *spec
			if err := RestrictALPN(&restricted, tt.protos); err != nil {
				t.Fatal(err)
			}
			alpn, alps := alpnOf(&restricted)
			if !slices.Equal(alpn, tt.wantALPN) || !slices.Equal(alps, tt.wantALPS) {
				t.Fatalf("ALPN %v, ALPS %v; want %v, %v", alpn, alps, tt.wantALPN, tt.wantALPS)
			}
			// The extensions of the original spec, which may be shared, are
			// not modified.
			if a, s := alpnOf(&utls.ClientHelloSpec{Extensions: before}); !slices.Equal(a, origALPN) || !slices.Equal(s, origALPS) {
				t.Fatalf("original spec changed: ALPN %v, ALPS %v", a, s)
			}
			if want := len(before) - map[bool]int{true: 1, false: 0}[tt.wantALPS == nil]; len(restricted.Extensions) != want {
				t.Fatalf("%d extensions, want %d", len(restricted.Extensions), want)
			}
		})
	}
}

func TestRestrictALPNNoneOffered(t *testing.T) {
	spec := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{&utls.ALPNExtension{AlpnProtocols: []string{ProtoHTTP1}}}}
	if err := RestrictALPN(spec, []string{ProtoH2}); !errors.Is(err, ErrNoProtocol) {
		t.Fatalf("err = %v, want ErrNoProtocol", err)
	}
}

// Without ALPN there is nothing to restrict, ALPS included.
func TestRestrictALPNWithoutALPN(t *testing.T) {
	alps := &utls.ApplicationSettingsExtension{SupportedProtocols: []string{ProtoH2}}
	spec := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{&utls.SNIExtension{}, alps}}
	if err := RestrictALPN(spec, []string{ProtoHTTP1}); err != nil {
		t.Fatal(err)
	}
	if len(spec.Extensions) != 2 || spec.Extensions[1] != alps {
		t.Fatalf("spec changed: %v", spec.Extensions)
	}
}
