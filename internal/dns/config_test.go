package dns

import (
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// env returns a lookup of the variables of m.
func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func servers(addrs ...string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, a := range addrs {
		out = append(out, netip.AddrPortFrom(netip.MustParseAddr(a), 53))
	}
	return out
}

func sameConfig(a, b Config) bool {
	return slices.Equal(a.Servers, b.Servers) && slices.Equal(a.Search, b.Search) &&
		a.Ndots == b.Ndots && a.Attempts == b.Attempts && a.Rotate == b.Rotate &&
		a.Unhandled == b.Unhandled && maps.Equal(a.Hosts, b.Hosts)
}

func TestResolvConf(t *testing.T) {
	local := servers("127.0.0.1")
	def := func(c Config) Config {
		if c.Servers == nil {
			c.Servers = local
		}
		if c.Ndots == 0 {
			c.Ndots = 1
		}
		if c.Attempts == 0 {
			c.Attempts = 2
		}
		return c
	}
	long := func(c byte, n int) string { return strings.Repeat(string(c), n) }
	tests := []struct {
		name     string
		data     string
		env      map[string]string
		hostname string
		want     Config
		ok       bool
	}{
		{name: "empty", hostname: "box", want: def(Config{}), ok: true},
		{name: "hostname domain", hostname: "box.example.com", want: def(Config{Search: []string{"example.com"}}), ok: true},
		{name: "hostname final dot", hostname: "box.", want: def(Config{Search: []string{""}}), ok: true},
		{
			name: "servers and search",
			data: "nameserver 10.0.0.1 x\nnameserver\t10.0.0.2\ttrailing\nsearch a.example  b.example \n",
			want: def(Config{Servers: servers("10.0.0.1", "10.0.0.2"), Search: []string{"a.example", "b.example"}}),
			ok:   true,
		},
		{
			name:     "file search over hostname",
			data:     "search a",
			hostname: "box.example.com",
			want:     def(Config{Search: []string{"a"}}),
			ok:       true,
		},
		{name: "domain after search", data: "search a b\ndomain c\td\n", want: def(Config{Search: []string{"c"}}), ok: true},
		{name: "domain with a space", data: "domain c d\n", want: def(Config{Search: []string{"c"}}), ok: true},
		{name: "search after domain", data: "domain c\nsearch\ta \tb\n", want: def(Config{Search: []string{"a", "b"}}), ok: true},
		{name: "domain ends at newline", data: "domain c\n", want: def(Config{Search: []string{"c"}}), ok: true},
		{
			name: "empty lists",
			data: "search a\nsearch \t\ndomain \ndomain\t\t\nsearch  ",
			want: def(Config{Search: []string{"a"}}),
			ok:   true,
		},
		{
			name: "keywords",
			data: "#nameserver 1.1.1.1\n;nameserver 1.1.1.2\n nameserver 1.1.1.3\nnameserverx 1.1.1.5\nnameserver\nnameserver \nsearchx a\nsearch\nnameserver 1.1.1.4",
			want: def(Config{Servers: servers("1.1.1.4")}),
			ok:   true,
		},
		{
			name: "carriage returns",
			data: "nameserver 10.0.0.9\r\nnameserver 10.0.0.8\v\nsearch a\tb\v c\r\n",
			want: def(Config{Search: []string{"a", "b\v", "c\r"}}),
			ok:   true,
		},
		{
			name: "NUL",
			data: "nameserver 10.0.0.1\x00junk\nsearch a\x00 b\n\x00nameserver 10.0.0.2\n",
			want: def(Config{Servers: servers("10.0.0.1"), Search: []string{"a"}}),
			ok:   true,
		},
		{
			name:     "LOCALDOMAIN",
			data:     "search a\ndomain b\n",
			env:      map[string]string{"LOCALDOMAIN": " x \t y\nz"},
			hostname: "box.example.com",
			want:     def(Config{Search: []string{"", "x", "y"}}),
			ok:       true,
		},
		{
			name:     "empty LOCALDOMAIN",
			hostname: "box.example.com",
			env:      map[string]string{"LOCALDOMAIN": ""},
			want:     def(Config{Search: []string{""}}),
			ok:       true,
		},
		{
			name: "six search names",
			data: "search a b c d e f g\n",
			want: def(Config{Search: []string{"a", "b", "c", "d", "e", "f"}}),
			ok:   true,
		},
		{
			name: "search bytes",
			data: "search " + long('a', 127) + " " + long('b', 127) + " c\n",
			want: def(Config{Search: []string{long('a', 127), long('b', 127)}}),
			ok:   true,
		},
		{name: "search name too long", data: "search " + long('a', 256) + " b\n", want: def(Config{}), ok: true},
		{name: "search name of 255 bytes", data: "search " + long('a', 255) + " b\n", want: def(Config{Search: []string{long('a', 255)}}), ok: true},
		{
			name: "three servers",
			data: "nameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 10.0.0.3\nnameserver 0.0.0.0\n",
			want: def(Config{Servers: servers("10.0.0.1", "10.0.0.2", "10.0.0.3")}),
			ok:   true,
		},
		{
			name: "IPv6",
			data: "nameserver fe80::1%eth0\nnameserver 2001:db8::1%eth0\nnameserver ::ffff:1.2.3.4\n",
			want: def(Config{Servers: []netip.AddrPort{
				netip.MustParseAddrPort("[fe80::1%eth0]:53"),
				netip.MustParseAddrPort("[2001:db8::1]:53"),
				netip.MustParseAddrPort("[::ffff:1.2.3.4]:53"),
			}}),
			ok: true,
		},
		{
			name: "inet_aton",
			data: "nameserver 10.1\nnameserver 1.2.3.4%x\nnameserver 0x7f.1\nnameserver 012.0.0.1\n",
			want: def(Config{Servers: servers("10.0.0.1", "127.0.0.1", "10.0.0.1")}),
			ok:   true,
		},
		{name: "options", data: "options ndots:3 attempts:4 rotate\n", want: def(Config{Ndots: 3, Attempts: 4, Rotate: true}), ok: true},
		{name: "options capped", data: "options ndots:20 attempts:9\n", want: def(Config{Ndots: 15, Attempts: 5}), ok: true},
		{name: "options zero", data: "options ndots:0 attempts:0\n", want: Config{Servers: local}, ok: true},
		{name: "options negative", data: "options ndots:-1 attempts:-1\n", want: def(Config{Ndots: 15, Attempts: -1}), ok: true},
		{name: "ndots in 4 bits", data: "options ndots:-14\n", want: def(Config{Ndots: 2}), ok: true},
		{
			name: "options words",
			data: "options\tndots:\v4\t\tattempts:3\nnameserver 10.0.0.1\noptions rotatex",
			want: def(Config{Servers: servers("10.0.0.1"), Ndots: 4, Attempts: 3, Rotate: true}),
			ok:   true,
		},
		{name: "options last wins", data: "options ndots:3\noptions ndots:4\n", want: def(Config{Ndots: 4}), ok: true},
		{
			name: "RES_OPTIONS after the file",
			data: "options ndots:3 attempts:4\n",
			env:  map[string]string{"RES_OPTIONS": "ndots:5"},
			want: def(Config{Ndots: 5, Attempts: 4}),
			ok:   true,
		},
		{name: "use-vc", data: "options use-vc\n", want: def(Config{Unhandled: true}), ok: true},
		{name: "use-vc from RES_OPTIONS", env: map[string]string{"RES_OPTIONS": "use-vcx"}, want: def(Config{Unhandled: true}), ok: true},
		{
			name: "use-vc before the servers",
			data: "nameserver 0.0.0.0\noptions use-vc\n",
			want: def(Config{Servers: servers("0.0.0.0"), Unhandled: true}),
			ok:   true,
		},
		{name: "unspecified IPv4", data: "nameserver 10.0.0.1\nnameserver 0.0.0.0\n"},
		{name: "unspecified IPv6", data: "nameserver ::\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseResolvConf(tt.data, env(tt.env), tt.hostname)
			if ok != tt.ok || !sameConfig(got, tt.want) {
				t.Errorf("parseResolvConf = %+v, %v; want %+v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestStrtol(t *testing.T) {
	for s, want := range map[string]int{
		"":                       0,
		"x":                      0,
		"-":                      0,
		"+-3":                    0,
		"12x":                    12,
		" \t\n\v\f\r+7":          7,
		"-3":                     -3,
		"4294967297":             1,
		"99999999999":            1215752191,
		"9223372036854775807":    -1,
		"9223372036854775808":    -1,
		"99999999999999999999":   -1,
		"-9223372036854775808":   0,
		"-99999999999999999999":  0,
		"-9223372036854775807":   1,
		"922337203685477580":     -858993460,
		"9223372036854775806000": -1,
	} {
		if got := strtol(s); got != want {
			t.Errorf("strtol(%q) = %d, want %d", s, got, want)
		}
	}
}

func TestInetAton(t *testing.T) {
	for s, want := range map[string]string{
		"1.2.3.4":      "1.2.3.4",
		"1":            "0.0.0.1",
		"0":            "0.0.0.0",
		"00":           "0.0.0.0",
		"0x0":          "0.0.0.0",
		"0xffffffff":   "255.255.255.255",
		"4294967295":   "255.255.255.255",
		"1.0xffffff":   "1.255.255.255",
		"1.2.0xffff":   "1.2.255.255",
		"1.2.3.0xff":   "1.2.3.255",
		"16909060":     "1.2.3.4",
		"1.0x020304":   "1.2.3.4",
		"1.2.0x0304":   "1.2.3.4",
		"1.2.3.4.0":    "",
		"1.2.3.4.0.0":  "",
		"0377.0.0.1":   "255.0.0.1",
		"0X7F.0.0.01":  "127.0.0.1",
		"0xFF.1":       "255.0.0.1",
		"":             "",
		"1.2.3.4.5":    "",
		"256.1.1.1":    "",
		"1.16777216":   "",
		"1.2.65536":    "",
		"1.2.3.256":    "",
		"0x":           "",
		"08":           "",
		"1..2":         "",
		"1.":           "",
		".1":           "",
		"1.2.3.4 ":     "",
		"4294967296":   "",
		"0x100000000":  "",
		"+1":           "",
		"1.2.3.-4":     "",
		"a":            "",
		"0xg":          "",
		"1_0":          "",
		"0x1_0":        "",
		"1.2.3.4%eth0": "",
	} {
		got := ""
		if a, ok := inetAton(s); ok {
			got = a.String()
		}
		if got != want {
			t.Errorf("inetAton(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestNsswitch(t *testing.T) {
	resolved := servers("127.0.0.53")
	other := servers("10.0.0.1")
	tests := []struct {
		data    string
		servers []netip.AddrPort
		want    bool
	}{
		{"", other, true},
		{"passwd: files\n", other, true},
		{"hosts:\n", other, true},
		{"hosts: \t\nhosts: dns", other, true},
		{"hosts: files dns", other, true},
		{"HOSTS:files\tDNS", other, true},
		{"HOSTS: dns", other, false},
		{"\n  \t hosts: Files Dns  \n", other, true},
		{"\n  \t hosts: dns", other, false},
		{"passwd: files\n\nhosts: files dns\n", other, true},
		{"xhosts: dns\nhosts: files dns", other, true},
		{"# hosts: dns\nhosts: files dns", other, true},
		{"hosts: dns\nhosts: files dns", other, false},
		{"hosts: dns files", other, false},
		{"hosts: files", other, false},
		{"hosts: files files dns", other, false},
		{"hosts: files mdns4_minimal [NOTFOUND=return] dns myhostname", other, true},
		{"hosts: files mdns_minimal mdns6_minimal dns", other, true},
		{"hosts: files mdns4_minimal [UNAVAIL=return] dns", other, false},
		{"hosts: files mdns dns", other, false},
		{"hosts: files mdns4 dns", other, false},
		{"hosts: files mdns6 dns", other, false},
		{"hosts: files nis dns", other, false},
		{"hosts: files foo dns", other, false},
		{"hosts: files myhostname dns", other, true},
		{"hosts: files myhostname [SUCCESS=continue] dns", other, true},
		{"hosts: files myhostname [NOTFOUND=return] dns", other, false},
		{"hosts: files myhostname [UNAVAIL=return] dns", other, false},
		{"hosts: files myhostname [TRYAGAIN=return] dns", other, false},
		{"hosts: files [NOTFOUND=return] dns", other, false},
		{"hosts: files [SUCCESS=continue] dns", other, false},
		{"hosts: files [UNAVAIL=return] dns", other, false},
		{"hosts: files [TRYAGAIN=return] dns", other, false},
		{"hosts: files [!SUCCESS=continue] dns", other, true},
		{"hosts: files [!SUCCESS=return] dns", other, false},
		{"hosts: files dns [NOTFOUND=return]", other, true},
		{"hosts: files dns [SUCCESS=continue]", other, false},
		{"hosts: files dns [!SUCCESS=return]", other, true},
		{"hosts: files dns [!NOTFOUND=continue]", other, false},
		{"hosts: files dns [NOTFOUND=return NOTFOUND=continue]", other, false},
		{"hosts: files dns [!SUCCESS=return NOTFOUND=continue]", other, false},
		{"hosts: files dns [SUCCESS=return SUCCESS=return]", other, true},
		{"hosts: files dns [NOTFOUND=foo]", other, false},
		{"hosts: files dns [FOO=return]", other, false},
		{"hosts: files dns [NOTFOUND]", other, false},
		{"hosts: files dns [NOTFOUND=return=x]", other, false},
		{"hosts: files dns [!=return]", other, false},
		{"hosts: files dns [notfound=MERGE]", other, true},
		{"hosts: files dns [success=MERGE]", other, false},
		{"hosts: files dns [success=CONTINUE]", other, false},
		{"hosts: files dns [ SUCCESS=continue ]", other, false},
		{"hosts: files dns [[ SUCCESS=continue]", other, false},
		{"hosts: files dns [ [NOTFOUND=return]", other, true},
		{"hosts: files dns [SUCCESS=continue", other, false},
		{"hosts: files dns [] myhostname", other, true},
		{"hosts: files dns []]  [SUCCESS=continue]", other, false},
		{"hosts: files dns [] ] [SUCCESS=continue]", other, false},
		{"hosts: [NOTFOUND=return] files dns", other, false},
		{"hosts: files dns # comment", other, true},
		{"hosts: files # dns", other, false},
		{"hosts: resolve dns", resolved, true},
		{"hosts: resolve", resolved, true},
		{"hosts: files resolve [!UNAVAIL=return] dns", resolved, true},
		{"hosts: files resolve [SUCCESS=continue] dns", resolved, false},
		{"hosts: resolve", other, false},
		{"hosts: resolve", servers("127.0.0.53", "10.0.0.1"), false},
		{"hosts: myhostname", other, false},
	}
	for _, tt := range tests {
		if got := nsswitchCompatible(parseNsswitch(tt.data), tt.servers); got != tt.want {
			t.Errorf("nsswitchCompatible(%q, %v) = %v, want %v", tt.data, tt.servers, got, tt.want)
		}
	}
}

func TestHosts(t *testing.T) {
	v4 := func(n string) HostsKey { return HostsKey{n, false} }
	v6 := func(n string) HostsKey { return HostsKey{n, true} }
	ip := netip.MustParseAddr
	tests := []struct {
		name string
		data string
		want map[HostsKey]netip.Addr
	}{
		{"empty", "", map[HostsKey]netip.Addr{}},
		{
			"lines",
			"127.0.0.1 localhost box\n::1\tlocalhost ip6-localhost\r\n10.0.0.1 a.example # b.example\n",
			map[HostsKey]netip.Addr{
				v4("localhost"): ip("127.0.0.1"), v4("box"): ip("127.0.0.1"),
				v6("localhost"): ip("::1"), v6("ip6-localhost"): ip("::1"),
				v4("a.example"): ip("10.0.0.1"),
			},
		},
		{
			"first address wins",
			"10.0.0.1 a\n10.0.0.2 a b\n",
			map[HostsKey]netip.Addr{v4("a"): ip("10.0.0.1"), v4("b"): ip("10.0.0.2")},
		},
		{
			"comments",
			"# 10.0.0.1 a\n10.0.0.2 b#c\n  # 10.0.0.3 d\n10.0.0.4 e # f",
			map[HostsKey]netip.Addr{v4("b"): ip("10.0.0.2"), v4("e"): ip("10.0.0.4")},
		},
		{
			"bad address skips the line",
			"10.0.0.1 a\nbad b c\n10.0.0.1%x d\nfe80::1%eth0 e\n",
			map[HostsKey]netip.Addr{v4("a"): ip("10.0.0.1")},
		},
		{
			"URL forms of IPv4",
			"0x7f.1 a\n012.0.0.1 b\n10.1. c\n",
			map[HostsKey]netip.Addr{v4("a"): ip("127.0.0.1"), v4("b"): ip("10.0.0.1"), v4("c"): ip("10.0.0.1")},
		},
		{
			"mapped IPv6",
			"::ffff:1.2.3.4 a\n",
			map[HostsKey]netip.Addr{v6("a"): ip("::ffff:1.2.3.4")},
		},
		{
			"line starting with a blank",
			"10.0.0.1 a\n  10.0.0.2 b\n\t10.0.0.3\tc",
			map[HostsKey]netip.Addr{v4("a"): ip("10.0.0.1"), v4("b"): ip("10.0.0.2"), v4("c"): ip("10.0.0.3")},
		},
		{
			"carriage return",
			"10.0.0.1 a\r10.0.0.2 b\r\n",
			map[HostsKey]netip.Addr{v4("a"): ip("10.0.0.1"), v4("b"): ip("10.0.0.2")},
		},
		{
			"names",
			"10.0.0.1 UPPER.Example. under_score -a.b 1.2.3.4 ::1 host:80 a..b bücher.example 0x1 x.123 " + strings.Repeat("a", 64) + "\n",
			map[HostsKey]netip.Addr{
				v4("upper.example."): ip("10.0.0.1"), v4("under_score"): ip("10.0.0.1"), v4("-a.b"): ip("10.0.0.1"),
				v4("xn--bcher-kva.example"): ip("10.0.0.1"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseHosts(tt.data); !maps.Equal(got, tt.want) {
				t.Errorf("parseHosts = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompliant(t *testing.T) {
	label := strings.Repeat("a", 63)
	name253 := label + "." + label + "." + label + "." + strings.Repeat("a", 61)
	for host, want := range map[string]bool{
		"a":            true,
		"a.b":          true,
		"a.b.":         true,
		"a-b_c.d":      true,
		"-a._b.c":      true,
		"a.-b":         false,
		"a._b":         false,
		"1.2":          true,
		"":             false,
		".":            false,
		"a..b":         false,
		".a":           false,
		"a.b..":        false,
		"a b":          false,
		"a/b":          false,
		"A":            false,
		label:          true,
		label + "a":    false,
		label + ".":    true,
		label + "a.":   false,
		label + "a.b":  false,
		name253:        true,
		name253 + ".":  true,
		name253 + "a":  false,
		name253 + "a.": false,
	} {
		if got := compliant(host); got != want {
			t.Errorf("compliant(%q) = %v, want %v", host, got, want)
		}
	}
}

// files is a file system for load. A file with an error is read in part:
// its contents are to be ignored.
type files map[string]any // []byte or error

func (f files) read(name string) ([]byte, error) {
	switch v := f[name].(type) {
	case []byte:
		return v, nil
	case error:
		return []byte("nameserver 0.0.0.0\nhosts: dns\n"), &fs.PathError{Op: "read", Path: name, Err: v}
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func TestLoad(t *testing.T) {
	resolv := []byte("nameserver 10.0.0.1\n")
	hosts := []byte("10.0.0.2 a\n")
	base := Config{Servers: servers("10.0.0.1"), Ndots: 1, Attempts: 2, Hosts: map[HostsKey]netip.Addr{{"a", false}: netip.MustParseAddr("10.0.0.2")}}
	with := func(f func(*Config)) Config {
		c := base
		f(&c)
		return c
	}
	tests := []struct {
		name  string
		files files
		want  Config
		ok    bool
	}{
		{"files", files{resolvConf: resolv, nsswitchConf: []byte("hosts: files dns\n"), hostsFile: hosts}, base, true},
		{"no nsswitch.conf", files{resolvConf: resolv, hostsFile: hosts}, base, true},
		{
			"nsswitch.conf unreadable",
			files{resolvConf: resolv, nsswitchConf: syscall.EACCES, hostsFile: hosts},
			base, true,
		},
		{
			"nsswitch.conf too large",
			files{resolvConf: resolv, nsswitchConf: []byte("hosts: dns\n" + strings.Repeat("#", 1<<20-10)), hostsFile: hosts},
			base, true,
		},
		{
			"nsswitch.conf at the limit",
			files{resolvConf: resolv, nsswitchConf: []byte("hosts: dns\n" + strings.Repeat("#", 1<<20-11)), hostsFile: hosts},
			with(func(c *Config) { c.Unhandled = true }), true,
		},
		{
			"incompatible nsswitch.conf",
			files{resolvConf: resolv, nsswitchConf: []byte("hosts: dns files\n"), hostsFile: hosts},
			with(func(c *Config) { c.Unhandled = true }), true,
		},
		{
			"unhandled resolv.conf",
			files{resolvConf: []byte("nameserver 10.0.0.1\noptions use-vc\n"), hostsFile: hosts},
			with(func(c *Config) { c.Unhandled = true }), true,
		},
		{
			"no resolv.conf",
			files{hostsFile: hosts},
			with(func(c *Config) { c.Servers = servers("127.0.0.1") }), true,
		},
		{"refused resolv.conf", files{resolvConf: []byte("nameserver 0.0.0.0\n"), hostsFile: hosts}, Config{}, false},
		{"resolv.conf error", files{resolvConf: syscall.EMFILE, hostsFile: hosts}, Config{}, false},
		{
			"no hosts file",
			files{resolvConf: resolv},
			with(func(c *Config) { c.Hosts = map[HostsKey]netip.Addr{} }), true,
		},
		{"hosts file error", files{resolvConf: resolv, hostsFile: syscall.EACCES}, Config{}, false},
		{"hosts file too large", files{resolvConf: resolv, hostsFile: make([]byte, 1<<25+1)}, Config{}, false},
		{
			"hosts file at the limit",
			files{resolvConf: resolv, hostsFile: []byte(string(hosts) + strings.Repeat("#", 1<<25-len(hosts)))},
			base, true,
		},
	}
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM, syscall.EISDIR, syscall.ELOOP, syscall.ENOTDIR} {
		tests = append(tests, struct {
			name  string
			files files
			want  Config
			ok    bool
		}{
			fmt.Sprint("resolv.conf ", errno),
			files{resolvConf: errno, hostsFile: hosts},
			with(func(c *Config) { c.Servers = servers("127.0.0.1") }), true,
		})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := load(tt.files.read, env(nil), "box")
			if ok != tt.ok || !sameConfig(got, tt.want) {
				t.Errorf("load = %+v, %v; want %+v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestLoadEnv(t *testing.T) {
	read := files{resolvConf: []byte("search a\n")}.read
	c, ok := load(read, env(map[string]string{"LOCALDOMAIN": "b", "RES_OPTIONS": "ndots:3"}), "box.c")
	if !ok || !slices.Equal(c.Search, []string{"b"}) || c.Ndots != 3 {
		t.Errorf("load = %+v, %v; want the search list b and ndots 3", c, ok)
	}
	c, ok = load(files{}.read, env(nil), "box.c")
	if !ok || !slices.Equal(c.Search, []string{"c"}) {
		t.Errorf("load = %+v, %v; want the search list c", c, ok)
	}
}

func TestSystem(t *testing.T) {
	t.Setenv("LOCALDOMAIN", "eidolon.test")
	t.Setenv("RES_OPTIONS", "ndots:7")
	c, ok := System()
	if !ok || !slices.Equal(c.Search, []string{"eidolon.test"}) || c.Ndots != 7 {
		t.Errorf("System = %+v, %v; want the search list and ndots of the environment", c, ok)
	}
}
