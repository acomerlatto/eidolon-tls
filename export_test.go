package eidolon

import "github.com/acomerlatto/eidolon-tls/internal/dns"

// The tests do not ask the name servers of the system.
func init() {
	systemDNS = func() (dns.Config, bool) { return dns.Config{}, false }
}
