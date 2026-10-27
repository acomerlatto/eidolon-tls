package tlsdial

import (
	"errors"
	"slices"

	utls "github.com/acomerlatto/utls"
)

// ErrNoProtocol reports a spec whose ALPN extension offers none of the
// enabled protocols.
var ErrNoProtocol = errors.New("tlsdial: the ClientHello offers none of the enabled protocols")

// RestrictALPN keeps in the ALPN extension of spec only the protocols in
// protos, in the spec's order. ALPS keeps only the protocols ALPN still
// offers and is left out when none remains: Chromium registers ALPS by
// walking the ALPN list, so it never sends settings for a protocol it does
// not offer.
//
// Changed extensions are replaced by copies; the ones in spec may be
// shared. A spec without ALPN is left as it is.
func RestrictALPN(spec *utls.ClientHelloSpec, protos []string) error {
	var offered []string
	found := false
	exts := make([]utls.TLSExtension, 0, len(spec.Extensions))
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			found = true
			offered = filter(alpn.AlpnProtocols, protos)
			if len(offered) == 0 {
				return ErrNoProtocol
			}
			ext = &utls.ALPNExtension{AlpnProtocols: offered}
		}
		exts = append(exts, ext)
	}
	if !found {
		return nil
	}
	out := exts[:0]
	for _, ext := range exts {
		switch alps := ext.(type) {
		case *utls.ApplicationSettingsExtension:
			c := *alps
			if c.SupportedProtocols = filter(alps.SupportedProtocols, offered); len(c.SupportedProtocols) == 0 {
				continue
			}
			ext = &c
		case *utls.ApplicationSettingsExtensionNew:
			c := *alps
			if c.SupportedProtocols = filter(alps.SupportedProtocols, offered); len(c.SupportedProtocols) == 0 {
				continue
			}
			ext = &c
		}
		out = append(out, ext)
	}
	spec.Extensions = out
	return nil
}

// filter returns the elements of list that are in keep, in list's order.
func filter(list, keep []string) []string {
	var out []string
	for _, p := range list {
		if slices.Contains(keep, p) {
			out = append(out, p)
		}
	}
	return out
}
