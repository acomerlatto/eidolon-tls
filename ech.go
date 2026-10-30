package eidolon

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/target"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// ECHMode is the policy of Encrypted Client Hello (RFC 9849), as the
// EchMode of Chrome 156.
type ECHMode int

const (
	// ECHAuto, the default, offers ECH to an origin with an ECH
	// configuration, from WithECHConfig or else from its HTTPS record, and
	// sends the GREASE ECH of the profile to the others, as Chrome
	// (kOpportunistic). The record is asked to the server of WithDoH, or,
	// on Linux and a direct connection (no proxy, no WithDialContext), to
	// the name servers of the system as Chrome on Linux does: those of
	// /etc/resolv.conf, by UDP, unless Chrome would leave the resolution
	// to the system (use-vc, an nsswitch.conf it does not follow) or the
	// host is localhost or in /etc/hosts. The configuration is read when
	// the client is made; the name is asked as it is, without the search
	// list. A record that cannot be looked up, or whose
	// configurations the client cannot use, leaves the origin with GREASE;
	// one whose ECHConfigList cannot be read fails with
	// ErrInvalidECHConfig, as in Chrome. When the server
	// rejects ECH, authenticated by a certificate for the public name of
	// the configuration, the request goes over one new connection, within
	// the same dial deadline and to the same IP address (see
	// WithDialContext): with the retry configurations the server
	// sent, or, without usable ones, with the GREASE ECH of the profile,
	// as Chrome does (RFC 9849, Section 6.1.6, would disable ECH). The
	// rejected connection carries no HTTP byte; a second rejection fails
	// with ErrECHRejected. Retry configurations are not kept: the next
	// connection starts from WithECHConfig again.
	ECHAuto ECHMode = iota
	// ECHRequired completes a request only over a connection whose server
	// accepted ECH, as Chrome's kStrict: a request to an origin without an
	// ECH configuration, http:// included, fails with ErrECHRequired
	// before any dial, and GREASE ECH does not count. An HTTPS record that
	// could not be looked up fails with ErrDNS. A rejection is
	// retried as in ECHAuto with the retry configurations; without usable
	// ones, the request fails with ErrECHRequired and ErrECHRejected.
	ECHRequired
	// ECHDisabled never offers ECH. The profile still sends its GREASE
	// ECH: unlike Chrome's kDisabled, which leaves the extension out, the
	// fingerprint of the profile does not change.
	ECHDisabled
)

// WithECHMode sets the ECH policy; the default is ECHAuto.
func WithECHMode(m ECHMode) Option {
	return func(c *config) error {
		switch m {
		case ECHAuto, ECHRequired, ECHDisabled:
		default:
			return fmt.Errorf("WithECHMode: unknown mode %d", m)
		}
		c.echMode = m
		return nil
	}
}

// WithECHConfig sets the ECHConfigList (RFC 9849, Section 4) of one
// origin, given by its authority: a host name, with an optional port, 443
// by default. Connections to https://authority offer ECH with it: the
// ClientHelloOuter carries the public name of the configuration, and the
// ClientHelloInner, encrypted, the host name and the profile's extensions,
// built as Chrome builds them. No other origin uses it, including the
// other ports of the host and the targets of redirects.
//
// New refuses, with ErrConfig, an IP address, an authority set twice, a
// list that cannot be read or has no configuration the client supports,
// a profile without the ECH extension, and ECHDisabled. The list is
// copied when WithECHConfig is called.
func WithECHConfig(authority string, configList []byte) Option {
	list := bytes.Clone(configList)
	return func(c *config) error {
		tgt, err := target.Parse(&url.URL{Scheme: "https", Host: authority})
		if err != nil {
			return fmt.Errorf("WithECHConfig: invalid authority %q: %w", authority, err)
		}
		if tgt.IsIP() {
			return fmt.Errorf("WithECHConfig: %q is an IP address; ECH needs a host name", authority)
		}
		if len(list) == 0 {
			return fmt.Errorf("WithECHConfig(%q): empty configuration list", authority)
		}
		if _, ok := c.ech[tgt.Origin()]; ok {
			return fmt.Errorf("WithECHConfig: %s set twice", tgt.Origin())
		}
		if c.ech == nil {
			c.ech = make(map[string][]byte)
		}
		c.ech[tgt.Origin()] = list
		return nil
	}
}

// configureECH sets the ECH policy of tr, after checking each
// configuration against the profile without connecting.
func (c *config) configureECH(tr *dispatch.Transport) error {
	if c.echMode == ECHDisabled && len(c.ech) > 0 {
		return errors.New("WithECHConfig with ECHDisabled")
	}
	tr.ECHRequired = c.echMode == ECHRequired
	// In order, so the same options report the same origin.
	for _, origin := range slices.Sorted(maps.Keys(c.ech)) {
		list := c.ech[origin]
		err := tlsdial.Check(tlsdial.Config{
			Spec: tr.Spec,
			TLS:  &utls.Config{EncryptedClientHelloConfigList: list},
		})
		if err != nil {
			return fmt.Errorf("WithECHConfig(%s): %w", origin, err)
		}
		if tr.ECH == nil {
			tr.ECH = make(map[string][]byte)
		}
		tr.ECH[origin] = list
	}
	return nil
}
