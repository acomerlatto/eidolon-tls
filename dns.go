package eidolon

import (
	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/dns"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// systemDNS reads the DNS configuration of the system.
var systemDNS = dns.System

// configureSystemDNS gives tr, when the client connects directly, a
// Resolver over the name servers of the system, as Chrome's built-in
// client on Linux: the HTTPS records of the origins are asked by UDP, and
// TCP after a truncated response, unless the host is in the hosts file or
// is localhost. Only HTTPS records are asked: the addresses still come
// from the system resolver.
//
// It does nothing with WithDoH, a proxy, which resolves the origins,
// WithDialContext, whose connections may go elsewhere, ECHDisabled, a
// profile that cannot offer ECH, or a system configuration Chrome would
// leave to the system resolver. The configuration is read once.
func (c *config) configureSystemDNS(tr *dispatch.Transport) {
	if c.doh != nil || c.proxy != nil || c.dialContext != nil || c.echMode == ECHDisabled {
		return
	}
	conf, ok := systemDNS()
	if !ok || conf.Unhandled {
		return
	}
	probe, err := echProbe()
	if err != nil {
		return
	}
	if tlsdial.Check(tlsdial.Config{Spec: tr.Spec, TLS: &utls.Config{EncryptedClientHelloConfigList: probe}}) != nil {
		return
	}
	tr.Resolver = &dns.Resolver{Exchanger: &dns.Classic{Config: conf}, Local: conf.Local}
}
