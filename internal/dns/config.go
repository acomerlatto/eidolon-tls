package dns

import (
	"errors"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/target"
)

// Limits of glibc's struct __res_state (resolv/bits/types/res_state.h),
// which Chrome reads: the name servers and search domains past them are
// ignored.
const (
	maxServers = 3  // MAXNS
	maxSearch  = 6  // MAXDNSRCH
	maxNdots   = 15 // RES_MAXNDOTS
	maxRetry   = 5  // RES_MAXRETRY
)

// FallbackPeriod is the period before a query goes to the next attempt:
// Chrome on Linux replaces the timeout option of resolv.conf with its
// default (kDnsDefaultFallbackPeriod).
const FallbackPeriod = time.Second

// Config is the configuration of the client, as Chrome builds it from the
// res_state glibc's res_ninit fills (ConvertResStateToDnsConfig).
type Config struct {
	// Servers are the name servers, on port 53.
	Servers []netip.AddrPort
	// Search is the search list of names with fewer than Ndots dots.
	Search []string
	// Ndots is the number of dots from which a name is first tried as
	// it is.
	Ndots int
	// Attempts is the number of attempts per server.
	Attempts int
	// Rotate starts each query on the next server.
	Rotate bool
	// Unhandled reports a configuration Chrome does not resolve with its
	// built-in client: an option it does not implement, or a name service
	// switch that does not consult DNS as it does. Chrome then leaves the
	// resolution to the system, without HTTPS queries.
	Unhandled bool
	// Hosts holds the addresses of /etc/hosts, by name and family.
	Hosts map[HostsKey]netip.Addr
}

// HostsKey is a name of the hosts file and its address family.
type HostsKey struct {
	Name string
	IPv6 bool
}

// Files read by System, and their limits in Chrome.
const (
	resolvConf   = "/etc/resolv.conf"
	nsswitchConf = "/etc/nsswitch.conf"
	hostsFile    = "/etc/hosts"
	maxNsswitch  = 1 << 20 // NsswitchReader kMaxFileSize
	maxHosts     = 1 << 25 // DnsHostsFileParser kMaxHostsSize
)

// System returns the configuration of the system as Chrome reads it on
// Linux (DnsConfigServiceLinux), or false when Chrome would have none and
// leave the resolution to the system.
func System() (Config, bool) {
	hostname, _ := os.Hostname()
	return load(os.ReadFile, os.LookupEnv, hostname)
}

// load builds the configuration from the files read by read. A resolv.conf
// that glibc cannot open for the contents of the file system counts as
// empty, a missing nsswitch.conf or hosts file as well, a nsswitch.conf too
// large as missing; another error, or a hosts file too large, leaves no
// configuration.
func load(read func(string) ([]byte, error), lookupEnv func(string) (string, bool), hostname string) (Config, bool) {
	resolv, err := read(resolvConf)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) &&
			!errors.Is(err, syscall.EISDIR) && !errors.Is(err, syscall.ELOOP) && !errors.Is(err, syscall.ENOTDIR) {
			return Config{}, false
		}
		resolv = nil
	}
	c, ok := parseResolvConf(string(resolv), lookupEnv, hostname)
	if !ok {
		return Config{}, false
	}
	nss, err := read(nsswitchConf)
	if err != nil || len(nss) > maxNsswitch {
		nss = nil
	}
	if !nsswitchCompatible(parseNsswitch(string(nss)), c.Servers) {
		c.Unhandled = true
	}
	hosts, err := read(hostsFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil || len(hosts) > maxHosts:
		return Config{}, false
	}
	c.Hosts = parseHosts(string(hosts))
	return c, true
}

// maxSearchBytes is the size of res_state's defdname, which holds the
// search list with a NUL after each name.
const maxSearchBytes = 256

// parseResolvConf reads resolv.conf as glibc's res_ninit does
// (resolv/res_init.c, release 2.39): LOCALDOMAIN replaces the search list,
// RES_OPTIONS adds options after the file, and without a search list the
// domain of hostname is used. Without a name server, glibc uses
// 127.0.0.1. It returns false for a configuration Chrome refuses, with a
// name server 0.0.0.0 or ::.
func parseResolvConf(data string, lookupEnv func(string) (string, bool), hostname string) (Config, bool) {
	c := Config{Ndots: 1, Attempts: 2}
	var servers []netip.AddrPort
	var search []string
	localDomain, haveEnv := lookupEnv("LOCALDOMAIN")
	if haveEnv {
		line, _, _ := strings.Cut(localDomain, "\n")
		search = splitNames(line)
	}
	var useVC bool
	for line := range strings.Lines(data) {
		// glibc reads the line as a C string. Comments, starting with ; or #,
		// match no keyword.
		line, _, _ = strings.Cut(line, "\x00")
		i := strings.IndexAny(line, " \t")
		if i < 0 {
			continue
		}
		key, rest := line[:i], strings.TrimLeft(line[i:], " \t")
		switch key {
		case "domain", "search":
			if haveEnv || rest == "" || rest[0] == '\n' {
				continue
			}
			if key == "domain" {
				search = []string{upTo(rest, " \t\n")}
			} else {
				line, _, _ := strings.Cut(rest, "\n")
				search = splitNames(line)
			}
		case "nameserver":
			if addr, ok := parseNameserver(upTo(rest, " \t\n")); ok {
				servers = append(servers, netip.AddrPortFrom(addr, 53))
			}
		case "options":
			setOptions(&c, &useVC, rest)
		}
	}
	if len(servers) == 0 {
		servers = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}
	}
	if len(search) == 0 {
		if _, domain, ok := strings.Cut(hostname, "."); ok {
			search = []string{domain}
		}
	}
	if options, ok := lookupEnv("RES_OPTIONS"); ok {
		setOptions(&c, &useVC, options)
	}

	c.Servers = servers[:min(len(servers), maxServers)]
	size := 0
	for i, name := range search {
		size += len(name) + 1
		if i == maxSearch || size > maxSearchBytes {
			search = search[:i]
			break
		}
	}
	c.Search = search
	// Chrome refuses use-vc (RES_USEVC), before it checks the name servers;
	// the other options it refuses cannot be set from resolv.conf.
	if useVC {
		c.Unhandled = true
		return c, true
	}
	for _, s := range c.Servers {
		if s.Addr().IsUnspecified() {
			return Config{}, false
		}
	}
	return c, true
}

// upTo returns s up to the first of chars.
func upTo(s, chars string) string {
	if i := strings.IndexAny(s, chars); i >= 0 {
		return s[:i]
	}
	return s
}

// splitNames splits a search list as glibc does: each run of bytes other
// than spaces and tabs is a name, and an empty name comes first when s is
// empty or starts with a blank.
func splitNames(s string) []string {
	names := strings.FieldsFunc(s, blank)
	if s == "" || blank(rune(s[0])) {
		names = append([]string{""}, names...)
	}
	return names
}

func blank(r rune) bool { return r == ' ' || r == '\t' }

// setOptions applies an options line as glibc's res_setoptions does: words
// are separated by spaces and tabs and matched by prefix, ndots and
// attempts are capped, and ndots is kept in 4 bits.
func setOptions(c *Config, useVC *bool, options string) {
	for _, opt := range strings.FieldsFunc(options, blank) {
		switch {
		case strings.HasPrefix(opt, "ndots:"):
			c.Ndots = maxNdots
			if n := strtol(opt[len("ndots:"):]); n <= maxNdots {
				c.Ndots = n & maxNdots
			}
		case strings.HasPrefix(opt, "attempts:"):
			c.Attempts = min(strtol(opt[len("attempts:"):]), maxRetry)
		case strings.HasPrefix(opt, "rotate"):
			c.Rotate = true
		case strings.HasPrefix(opt, "use-vc"):
			*useVC = true
		}
	}
}

// strtol returns the decimal number at the start of s as an int of C, as
// (int)strtol(s, NULL, 10) does: blanks, an optional sign, then digits,
// saturated to a long and truncated to an int; zero without digits.
func strtol(s string) int {
	s = strings.TrimLeft(s, " \t\n\v\f\r")
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	var n uint64
	for i := 0; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		n = min(n, 1<<63/10+1)*10 + uint64(s[i]-'0')
	}
	n = min(n, 1<<63)
	v := int64(min(n, 1<<63-1))
	if neg {
		v = -int64(n)
	}
	return int(int32(v))
}

// parseNameserver parses a name server as glibc does: an IPv4 address in
// any form inet_aton accepts, or an IPv6 address with an optional scope,
// which Chrome keeps for a link-local address only.
func parseNameserver(s string) (netip.Addr, bool) {
	if a, ok := inetAton(s); ok {
		return a, true
	}
	addr, zone, _ := strings.Cut(s, "%")
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is6() {
		return netip.Addr{}, false
	}
	if !a.IsLinkLocalUnicast() {
		zone = ""
	}
	return a.WithZone(zone), true
}

// inetAton parses an IPv4 address as glibc's __inet_aton_exact: one to four
// parts in decimal, octal (leading 0) or hexadecimal (leading 0x), the last
// one filling the remaining bytes, and nothing after them.
func inetAton(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var vals []uint64
	for _, p := range parts {
		base := 10
		switch {
		case len(p) > 1 && (p[:2] == "0x" || p[:2] == "0X"):
			base, p = 16, p[2:]
		case len(p) > 1 && p[0] == '0':
			base, p = 8, p[1:]
		}
		v, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		vals = append(vals, v)
	}
	last := len(vals) - 1
	for _, v := range vals[:last] {
		if v > 0xff {
			return netip.Addr{}, false
		}
	}
	if vals[last] >= 1<<(8*(4-last)) {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i, v := range vals[:last] {
		b[i] = byte(v)
	}
	for i := 3; i >= last; i-- {
		b[i] = byte(vals[last])
		vals[last] >>= 8
	}
	return netip.AddrFrom4(b), true
}

// Services of the hosts database of nsswitch.conf, as Chrome's
// NsswitchReader names them. mdns, mdns4, mdns6 and nis are incompatible as
// unknown services are.
const (
	svcUnknown = iota
	svcFiles
	svcDNS
	svcMDNSMinimal // mdns_minimal, mdns4_minimal, mdns6_minimal
	svcMyHostname
	svcResolve
)

// Statuses and actions of nsswitch.conf.
const (
	stUnknown = iota
	stSuccess
	stNotFound
	stUnavail
	stTryAgain
)

const (
	actUnknown = iota
	actReturn
	actContinue
	actMerge
)

type nssAction struct {
	negated        bool
	status, action int
}

type nssService struct {
	service int
	actions []nssAction
}

// parseNsswitch returns the services of the hosts database of
// nsswitch.conf, as Chrome's NsswitchReader::ReadAndParseHosts: files dns
// without the file or the database.
func parseNsswitch(data string) []nssService {
	hosts := ""
	found := false
	for text := data; text != ""; {
		text = strings.TrimLeft(text, " \t\n\v\f\r")
		if len(text) >= 6 && strings.EqualFold(text[:6], "hosts:") {
			line, _, _ := strings.Cut(text[6:], "\n")
			hosts, found = strings.Trim(line, " \t\n\v\f\r"), true
			break
		}
		_, text, _ = strings.Cut(text, "\n")
	}
	if !found || hosts == "" {
		return []nssService{{service: svcFiles}, {service: svcDNS}}
	}
	return tokenizeHosts(hosts)
}

// tokenizeHosts splits the services and [actions] of a database
// (TokenizeDatabase).
func tokenizeHosts(db string) []nssService {
	var out []nssService
	for db != "" {
		switch db[0] {
		case '#':
			return out
		case '[':
			if len(out) == 0 {
				out = append(out, nssService{service: svcUnknown})
			}
			end := strings.IndexByte(db, ']')
			var actions string
			if end < 0 {
				actions, db = db[1:], ""
			} else {
				actions, db = db[1:end], db[end:]
			}
			actions = strings.TrimLeft(actions, "[ \t\n\v\f\r")
			db = strings.TrimLeft(db, "] \t\n\v\f\r")
			for _, a := range strings.Fields(actions) {
				out[len(out)-1].actions = append(out[len(out)-1].actions, tokenizeAction(a))
			}
		default:
			end := strings.IndexAny(db, " \t\n\v\f\r")
			col := db
			if end >= 0 {
				col, db = db[:end], db[end:]
			} else {
				db = ""
			}
			out = append(out, nssService{service: serviceOf(col)})
		}
		db = strings.TrimLeft(db, " \t\n\v\f\r")
	}
	return out
}

func serviceOf(s string) int {
	switch strings.ToLower(s) {
	case "files":
		return svcFiles
	case "dns":
		return svcDNS
	case "mdns_minimal", "mdns4_minimal", "mdns6_minimal":
		return svcMDNSMinimal
	case "myhostname":
		return svcMyHostname
	case "resolve":
		return svcResolve
	}
	return svcUnknown
}

// tokenizeAction reads a STATUS=action column, ! negating the status.
func tokenizeAction(col string) nssAction {
	var a nssAction
	status, action, ok := strings.Cut(col, "=")
	if !ok {
		return a
	}
	// An action with = is unknown, as one without: Chrome splits the column
	// at each =.
	if s, ok := strings.CutPrefix(status, "!"); ok {
		a.negated, status = true, s
	}
	a.status = map[string]int{"success": stSuccess, "notfound": stNotFound, "unavail": stUnavail, "tryagain": stTryAgain}[strings.ToLower(status)]
	a.action = map[string]int{"return": actReturn, "continue": actContinue, "merge": actMerge}[strings.ToLower(action)]
	return a
}

// actionsAre reports whether actions, with the defaults of nsswitch.conf,
// give want for its statuses (AreActionsCompatible).
func actionsAre(actions []nssAction, want map[int]int) bool {
	got := make(map[int]int)
	var set func(a nssAction) bool
	set = func(a nssAction) bool {
		if a.negated {
			for _, st := range []int{stSuccess, stNotFound, stUnavail, stTryAgain} {
				if st != a.status && !set(nssAction{status: st, action: a.action}) {
					return false
				}
			}
			return true
		}
		if old, ok := got[a.status]; ok && old != a.action {
			return false
		}
		got[a.status] = a.action
		return true
	}
	for _, a := range actions {
		if a.status == stUnknown || a.action == actUnknown || !set(a) {
			return false
		}
	}
	for st, act := range map[int]int{stSuccess: actReturn, stNotFound: actContinue, stUnavail: actContinue, stTryAgain: actContinue} {
		if _, ok := got[st]; !ok {
			got[st] = act
		}
	}
	for st, act := range want {
		if got[st] != act {
			return false
		}
	}
	return true
}

// nsswitchCompatible reports whether the hosts database resolves as
// Chrome's built-in client does (IsNsswitchConfigCompatible): files once,
// then dns returning on success, with only services that cannot answer for
// the names Chrome resolves in between. resolve counts as files and dns
// when the only name server is systemd-resolved's.
func nsswitchCompatible(services []nssService, servers []netip.AddrPort) bool {
	files := false
	defaults := map[int]int{stSuccess: actReturn, stNotFound: actContinue, stUnavail: actContinue, stTryAgain: actContinue}
	for _, s := range services {
		switch s.service {
		case svcFiles:
			if files || !actionsAre(s.actions, defaults) {
				return false
			}
			files = true
		case svcResolve, svcDNS:
			if s.service == svcResolve {
				if len(servers) != 1 || servers[0] != netip.MustParseAddrPort("127.0.0.53:53") {
					return false
				}
				files = true
			}
			return files && actionsAre(s.actions, map[int]int{stSuccess: actReturn})
		case svcMDNSMinimal:
			if !actionsAre(s.actions, map[int]int{stUnavail: actContinue}) {
				return false
			}
		case svcMyHostname:
			if !actionsAre(s.actions, map[int]int{stNotFound: actContinue, stUnavail: actContinue, stTryAgain: actContinue}) {
				return false
			}
		default:
			return false
		}
	}
	return false
}

// parseHosts reads a hosts file as Chrome's ParseHosts on Linux: an IP
// address, then names, per line, # starting a comment; a line whose
// address does not parse is skipped. Names are canonicalized as URL hosts
// and the first address of a name and family is kept.
func parseHosts(data string) map[HostsKey]netip.Addr {
	hosts := make(map[HostsKey]netip.Addr)
	var ip netip.Addr
	nextIsIP := true
	for pos := 0; pos < len(data); {
		switch data[pos] {
		case ' ', '\t':
			pos++
		case '\r', '\n':
			nextIsIP = true
			pos++
		case '#':
			if i := strings.IndexByte(data[pos:], '\n'); i >= 0 {
				pos += i
			} else {
				pos = len(data)
			}
		default:
			end := strings.IndexAny(data[pos:], " \t\n\r#")
			if end < 0 {
				end = len(data) - pos
			}
			token := data[pos : pos+end]
			pos += end
			if !nextIsIP {
				if name, ok := hostsName(token); ok {
					key := HostsKey{name, ip.Is6()}
					if _, dup := hosts[key]; !dup {
						hosts[key] = ip
					}
				}
				continue
			}
			nextIsIP = false
			if a, ok := hostsIP(token); ok {
				ip = a
				continue
			}
			// Skip the rest of the line.
			if i := strings.IndexByte(data[pos:], '\n'); i >= 0 {
				pos += i
			} else {
				pos = len(data)
			}
		}
	}
	return hosts
}

// hostsIP parses the address of a line of the hosts file as Chrome's
// IPAddress::AssignFromIPLiteral: an IPv6 address without a zone when the
// token has ':', an IPv4 address in the forms of the URL standard
// otherwise.
func hostsIP(token string) (netip.Addr, bool) {
	if strings.Contains(token, ":") {
		a, err := netip.ParseAddr(token)
		return a, err == nil && a.Zone() == ""
	}
	a, err := target.ParseIPv4(token)
	return a, err == nil
}

// hostsName canonicalizes a name of the hosts file as a URL host, and
// refuses an IP address or a name Chrome would not resolve
// (IsCanonicalizedHostCompliant).
func hostsName(token string) (string, bool) {
	// Without brackets, a name with ':' is no host (CanonicalizeHost).
	if strings.Contains(token, ":") {
		return "", false
	}
	tgt, err := target.Parse(&url.URL{Scheme: "http", Host: token})
	if err != nil || tgt.IsIP() {
		return "", false
	}
	return tgt.Host, compliant(tgt.Host)
}

// compliant reports a host name Chrome resolves, as its
// IsCanonicalizedHostCompliant: labels of 1 to 63 letters, digits, hyphens
// and underscores, the last starting with a letter or digit, 253 bytes, or
// 254 with the final dot.
func compliant(host string) bool {
	if host == "" || len(host) > 254 || host[len(host)-1] != '.' && len(host) == 254 {
		return false
	}
	alnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	inLabel, startedAlnum, size := false, false, 0
	for i := 0; i < len(host); i++ {
		c := host[i]
		size++
		switch {
		case !inLabel:
			startedAlnum = alnum(c)
			if !startedAlnum && c != '-' && c != '_' {
				return false
			}
			inLabel = true
		case c == '.':
			inLabel = false
			// A label is never empty: a dot out of a label is refused above.
			if size > 64 {
				return false
			}
			size = 0
		case !alnum(c) && c != '-' && c != '_':
			return false
		}
	}
	return size <= 63 && startedAlnum
}
