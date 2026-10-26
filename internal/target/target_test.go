package target

import (
	"net/url"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		url                                 string
		host                                string
		port                                int
		authority, origin, addr, serverName string
	}{
		{url: "https://example.com/x", host: "example.com", port: 443,
			authority: "example.com", origin: "https://example.com", addr: "example.com:443", serverName: "example.com"},
		{url: "HTTPS://EXAMPLE.Com:443/", host: "example.com", port: 443,
			authority: "example.com", origin: "https://example.com", addr: "example.com:443", serverName: "example.com"},
		{url: "http://example.com:80", host: "example.com", port: 80,
			authority: "example.com", origin: "http://example.com", addr: "example.com:80", serverName: "example.com"},
		{url: "https://example.com:8443", host: "example.com", port: 8443,
			authority: "example.com:8443", origin: "https://example.com:8443", addr: "example.com:8443", serverName: "example.com"},
		{url: "https://example.com:/", host: "example.com", port: 443,
			authority: "example.com", origin: "https://example.com", addr: "example.com:443", serverName: "example.com"},
		{url: "https://user:pass@example.com/", host: "example.com", port: 443,
			authority: "example.com", origin: "https://example.com", addr: "example.com:443", serverName: "example.com"},
		{url: "https://example.com./", host: "example.com.", port: 443,
			authority: "example.com.", origin: "https://example.com.", addr: "example.com.:443", serverName: "example.com."},
		{url: "https://bücher.example/", host: "xn--bcher-kva.example", port: 443,
			authority: "xn--bcher-kva.example", origin: "https://xn--bcher-kva.example", addr: "xn--bcher-kva.example:443", serverName: "xn--bcher-kva.example"},
		// Non-transitional: ß is kept, not mapped to ss.
		{url: "https://faß.de/", host: "xn--fa-hia.de", port: 443,
			authority: "xn--fa-hia.de", origin: "https://xn--fa-hia.de", addr: "xn--fa-hia.de:443", serverName: "xn--fa-hia.de"},
		{url: "https://BÜCHER.example/", host: "xn--bcher-kva.example", port: 443,
			authority: "xn--bcher-kva.example", origin: "https://xn--bcher-kva.example", addr: "xn--bcher-kva.example:443", serverName: "xn--bcher-kva.example"},
		{url: "https://xn--bcher-kva.example/", host: "xn--bcher-kva.example", port: 443,
			authority: "xn--bcher-kva.example", origin: "https://xn--bcher-kva.example", addr: "xn--bcher-kva.example:443", serverName: "xn--bcher-kva.example"},
		{url: "https://under_score.example/", host: "under_score.example", port: 443,
			authority: "under_score.example", origin: "https://under_score.example", addr: "under_score.example:443", serverName: "under_score.example"},
		{url: "https://127.0.0.1:8443/", host: "127.0.0.1", port: 8443,
			authority: "127.0.0.1:8443", origin: "https://127.0.0.1:8443", addr: "127.0.0.1:8443", serverName: "127.0.0.1"},
		{url: "https://[2001:DB8:0:0::1]/", host: "2001:db8::1", port: 443,
			authority: "[2001:db8::1]", origin: "https://[2001:db8::1]", addr: "[2001:db8::1]:443", serverName: "2001:db8::1"},
		{url: "http://[::1]:8080/", host: "::1", port: 8080,
			authority: "[::1]:8080", origin: "http://[::1]:8080", addr: "[::1]:8080", serverName: "::1"},
		{url: "https://[::ffff:192.0.2.1]/", host: "192.0.2.1", port: 443,
			authority: "192.0.2.1", origin: "https://192.0.2.1", addr: "192.0.2.1:443", serverName: "192.0.2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Parse(u)
			if err != nil {
				t.Fatal(err)
			}
			if got.Host != tt.host || got.Port != tt.port {
				t.Errorf("Host, Port = %q, %d; want %q, %d", got.Host, got.Port, tt.host, tt.port)
			}
			if a := got.Authority(); a != tt.authority {
				t.Errorf("Authority = %q, want %q", a, tt.authority)
			}
			if o := got.Origin(); o != tt.origin {
				t.Errorf("Origin = %q, want %q", o, tt.origin)
			}
			if a := got.Addr(); a != tt.addr {
				t.Errorf("Addr = %q, want %q", a, tt.addr)
			}
			if s := got.ServerName(); s != tt.serverName {
				t.Errorf("ServerName = %q, want %q", s, tt.serverName)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	for _, raw := range []string{
		"ftp://example.com/",
		"https:///path",
		"https://example.com:0/",
		"https://example.com:65536/",
		"https://[fe80::1%25eth0]/",
		"https://exa mple.com/",
		"https://./",
		"https://a..b/",
	} {
		t.Run(raw, func(t *testing.T) {
			u, err := url.Parse(raw)
			if err != nil {
				return // already refused by net/url
			}
			if got, err := Parse(u); err == nil {
				t.Fatalf("Parse = %+v, want an error", got)
			}
		})
	}
}
