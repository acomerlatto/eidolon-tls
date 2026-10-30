package dispatch

import (
	"context"
	"errors"
	"fmt"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dns"
	"github.com/acomerlatto/eidolon-tls/internal/target"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// ErrDNS reports, with ECHRequired, an HTTPS record that could not be
// looked up, and, in any mode, an HTTPS record whose services all have ECH
// and none has an enabled protocol, which Chrome does not connect without
// (RFC 9460, Section 3).
var ErrDNS = errors.New("eidolon: DNS lookup failed")

// ErrInvalidECHConfig reports an HTTPS record whose ECHConfigList cannot
// be read, which fails the connection as Chrome's
// ERR_INVALID_ECH_CONFIG_LIST.
var ErrInvalidECHConfig = errors.New("eidolon: invalid ECHConfigList in the HTTPS record")

// echConfig returns the ECHConfigList a connection to tgt offers, before
// it is dialed: the one set for its origin, or else, with a Resolver, the
// one of its HTTPS record, as Chrome reads it (SSLConnectJob::DoSSLConnect,
// SSLClientSocketImpl::ConfigureEch). Nil sends the
// GREASE ECH of the profile; with ECHRequired, it is ErrECHRequired.
//
// The record gives the ECHConfigList of the first service, by priority,
// with an enabled protocol. When every service has one and none has an
// enabled protocol, the origin cannot be reached (SVCB-reliant). A lookup
// that failed sends GREASE, unless ECH is required. A list without
// a usable configuration sends GREASE too, unless ECH is required, and a
// malformed one fails.
func (t *Transport) echConfig(ctx context.Context, tgt target.Target) ([]byte, error) {
	if list := t.ECH[tgt.Origin()]; list != nil {
		return list, nil
	}
	if t.Resolver == nil || tgt.IsIP() {
		return t.noECH(tgt, nil)
	}
	h := t.Resolver.HTTPS(ctx, tgt.Host, uint16(tgt.Port))
	switch {
	case h.Status == dns.Failed && t.ECHRequired:
		return nil, fmt.Errorf("%w: HTTPS record of %s: %w", ErrDNS, tgt.Origin(), h.Err)
	case h.Status != dns.Found:
		return t.noECH(tgt, h.Err)
	}
	svc, ok := t.service(h.Services)
	if !ok {
		for _, s := range h.Services {
			if s.ECH == nil {
				return t.noECH(tgt, nil)
			}
		}
		return nil, fmt.Errorf("%w: the HTTPS record of %s has no service with an enabled protocol", ErrDNS, tgt.Origin())
	}
	if svc.ECH == nil {
		return t.noECH(tgt, nil)
	}
	err := tlsdial.Check(tlsdial.Config{Spec: t.Spec, TLS: &utls.Config{EncryptedClientHelloConfigList: svc.ECH}})
	switch {
	case err == nil:
		return svc.ECH, nil
	case errors.Is(err, utls.ErrMalformedECHConfigList):
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidECHConfig, tgt.Origin(), err)
	case errors.Is(err, utls.ErrNoUsableECHConfig):
		return t.noECH(tgt, err)
	}
	return nil, err
}

// noECH returns the configuration of a connection to tgt without one:
// nil, or ErrECHRequired with cause.
func (t *Transport) noECH(tgt target.Target, cause error) ([]byte, error) {
	switch {
	case !t.ECHRequired:
		return nil, nil
	case cause != nil:
		return nil, fmt.Errorf("%w: %s: %w", ErrECHRequired, tgt.Origin(), cause)
	}
	return nil, fmt.Errorf("%w: %s", ErrECHRequired, tgt.Origin())
}

// service returns the first service with an enabled protocol, as
// Chrome's IsEndpointUsableForTcpBasedAttempt.
func (t *Transport) service(services []dns.Service) (dns.Service, bool) {
	for _, s := range services {
		for _, p := range s.ALPN {
			if (p == tlsdial.ProtoH2 || p == tlsdial.ProtoHTTP1) && t.allows(p) {
				return s, true
			}
		}
	}
	return dns.Service{}, false
}
