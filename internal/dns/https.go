package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TypeHTTPS is the type of the HTTPS record (RFC 9460).
const TypeHTTPS = dnsmessage.TypeHTTPS

// Status classifies the answer to an HTTPS query, as Chrome tells its
// outcomes apart (HostResolverDnsTask): only Found carries services, and
// only Failed fails a request that requires ECH (IsFatalTransactionFailure);
// the others leave it without ECH.
type Status uint8

const (
	// Found: at least one record with a service Chrome uses.
	Found Status = iota
	// NoData: no service to use, for certain: no such name (NXDOMAIN), no
	// HTTPS record (NODATA), or compatible records without a service of
	// use, such as an AliasMode record, which Chrome does not follow.
	NoData
	// Incompatible: only records with a mandatory key Chrome does not
	// support (RFC 9460, Section 8).
	Incompatible
	// Invalid: an answer whose records cannot be read, or that do not
	// form one chain of CNAMEs from the name asked for.
	Invalid
	// Refused: the server answered FORMERR, NOTIMP, REFUSED or an unknown
	// error code.
	Refused
	// Failed: the server answered SERVFAIL, the answer is not an answer to
	// the query, or no answer came.
	Failed
)

var statusNames = [...]string{"found", "no data", "incompatible", "invalid", "refused", "failed"}

func (s Status) String() string {
	if int(s) < len(statusNames) {
		return statusNames[s]
	}
	return "Status(" + strconv.Itoa(int(s)) + ")"
}

// Service is a ServiceMode HTTPS record Chrome uses
// (ConnectionEndpointMetadata).
type Service struct {
	// Priority is the SvcPriority of the record.
	Priority uint16
	// ALPN holds the protocols of the alpn key, then http/1.1, the
	// default, unless no-default-alpn is set and it is not listed.
	ALPN []string
	// ECH is the ECHConfigList of the ech key, as it came; nil without it.
	ECH []byte
}

// HTTPS is the answer to an HTTPS query.
type HTTPS struct {
	Status Status
	// Services are the usable services of Found, by priority, records of
	// one priority in the order of the answer.
	Services []Service
	// TTL is how long the answer can be kept: the smallest TTL of the
	// records of the services for Found; of the compatible records, or
	// of the SOA records of the authority section, for NoData. Zero
	// means it cannot be kept, as the other statuses.
	TTL time.Duration
	// Err tells why, for Invalid, Refused and Failed.
	Err error
}

// errMismatch reports a response that is not an answer to the query.
var errMismatch = errors.New("dns: the response does not answer the query")

// SvcParamKeys Chrome reads (kSupportedKeys).
const (
	keyMandatory     = 0
	keyALPN          = 1
	keyNoDefaultALPN = 2
	keyPort          = 3
	keyIPv4Hint      = 4
	keyECH           = 5
	keyIPv6Hint      = 6
	keyTrustAnchors  = 13
)

// supportedKey reports whether a mandatory key leaves the record
// compatible (ServiceFormHttpsRecordRdata::IsCompatible).
func supportedKey(k uint16) bool {
	return k <= keyIPv6Hint || k == keyTrustAnchors
}

// Parse reads resp, the response to query, an HTTPS query of Query for
// the origin of host and port. It checks resp as Chrome's
// DnsResponse::InitParse does: the ID, the QR flag, one question, the
// same bytes as the question of query.
func Parse(query, resp []byte, host string, port uint16) HTTPS {
	qname, n, ok := readName(query, 12)
	if !ok || len(query) < 12+n+4 {
		return failed(errors.New("dns: invalid query"))
	}
	question := query[12 : 12+n+4]
	switch {
	case len(resp) < 12+len(question):
		return failed(errMismatch)
	case !bytes.Equal(resp[:2], query[:2]) || resp[2]&0x80 == 0 || binary.BigEndian.Uint16(resp[4:]) != 1:
		return failed(errMismatch)
	case !bytes.Equal(resp[12:12+len(question)], question):
		return failed(errMismatch)
	}
	switch rcode := dnsmessage.RCode(resp[3] & 0xf); rcode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	case dnsmessage.RCodeServerFailure:
		return failed(errors.New("dns: SERVFAIL"))
	default:
		return HTTPS{Status: Refused, Err: fmt.Errorf("dns: %v", rcode)}
	}
	m := &message{b: resp, off: 12 + len(question)}
	answers, authority := int(binary.BigEndian.Uint16(resp[6:])), int(binary.BigEndian.Uint16(resp[8:]))
	return extract(m, answers, authority, strings.ToLower(qname), host, port)
}

func failed(err error) HTTPS  { return HTTPS{Status: Failed, Err: err} }
func invalid(err error) HTTPS { return HTTPS{Status: Invalid, Err: err} }

// message reads the records of a response as Chrome's DnsRecordParser.
type message struct {
	b   []byte
	off int
}

// resource is a record as DnsRecordParser::ReadRecord reads it.
type resource struct {
	name       string
	typ, class uint16
	ttl        uint32
	data       []byte
	dataOff    int // of data in the message
}

// next reads a record; false at the end or at a malformed record.
func (m *message) next() (resource, bool) {
	name, n, ok := readName(m.b, m.off)
	if !ok || len(m.b)-m.off-n < 10 {
		return resource{}, false
	}
	h := m.b[m.off+n:]
	r := resource{
		name:  name,
		typ:   binary.BigEndian.Uint16(h),
		class: binary.BigEndian.Uint16(h[2:]),
		ttl:   binary.BigEndian.Uint32(h[4:]),
	}
	length := int(binary.BigEndian.Uint16(h[8:]))
	if len(h)-10 < length {
		return resource{}, false
	}
	r.dataOff = m.off + n + 10
	r.data = m.b[r.dataOff : r.dataOff+length]
	m.off = r.dataOff + length
	return r, true
}

// readName reads the name at off of msg as DnsRecordParser::ReadName:
// labels and compression pointers, anywhere in msg, up to 255 bytes of
// labels and their lengths. It returns the name, the bytes it takes at
// off, and false for a malformed name or a loop of pointers.
func readName(msg []byte, off int) (string, int, bool) {
	var labels []string
	start, consumed, jumps, size := off, 0, 0, 0
	for {
		if off >= len(msg) {
			return "", 0, false
		}
		switch msg[off] & 0xc0 {
		case 0xc0:
			if off > len(msg)-2 {
				return "", 0, false
			}
			if consumed == 0 {
				consumed = off + 2 - start
			}
			// A chain without loops has at most one pointer per two bytes.
			jumps++
			if jumps > len(msg)/2 {
				return "", 0, false
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
		case 0:
			n := int(msg[off])
			off++
			if n == 0 {
				if consumed == 0 {
					consumed = off - start
				}
				return strings.Join(labels, "."), consumed, true
			}
			size += 1 + n
			if size > 255 || n > len(msg)-off {
				return "", 0, false
			}
			labels = append(labels, string(msg[off:off+n]))
			off += n
		default:
			return "", 0, false
		}
	}
}

// record is an HTTPS record of an answer.
type record struct {
	name string // canonical
	ttl  uint32
	data []byte
}

// extract reads the answers and the authority section, as Chrome's
// ExtractResponseRecords and ExtractHttpsResults.
func extract(m *message, answers, authority int, qname, host string, port uint16) HTTPS {
	var records []record
	aliases := make(map[string]string) // CNAME owner → target, canonical
	for range answers {
		r, ok := m.next()
		if !ok {
			return invalid(errors.New("dns: malformed record"))
		}
		name := strings.ToLower(r.name)
		if !validRecordName(name) {
			return invalid(fmt.Errorf("dns: invalid record name %q", name))
		}
		// Records of a type Chrome reads need valid data, whatever their
		// class (RecordParsed::CreateFrom).
		switch r.typ {
		case uint16(dnsmessage.TypeA):
			if len(r.data) != 4 {
				return invalid(fmt.Errorf("dns: A record of %d bytes", len(r.data)))
			}
		case uint16(dnsmessage.TypeAAAA):
			if len(r.data) != 16 {
				return invalid(fmt.Errorf("dns: AAAA record of %d bytes", len(r.data)))
			}
		case uint16(dnsmessage.TypeCNAME):
			target, _, ok := readName(m.b, r.dataOff)
			if !ok {
				return invalid(errors.New("dns: malformed CNAME record"))
			}
			if r.class != uint16(dnsmessage.ClassINET) {
				continue
			}
			if _, dup := aliases[name]; dup {
				return invalid(fmt.Errorf("dns: two CNAME records for %s", name))
			}
			aliases[name] = strings.ToLower(target)
		case uint16(TypeHTTPS):
			if _, err := parseRecord(r.data); err != nil {
				return invalid(err)
			}
			if r.class == uint16(dnsmessage.ClassINET) {
				records = append(records, record{name, r.ttl, r.data})
			}
		}
	}
	// One chain of CNAMEs from the name asked for, to valid names, without
	// loops or CNAMEs off it, and the records at its end
	// (ValidateNamesAndAliases).
	final, n := qname, 0
	for ; n <= len(aliases); n++ {
		next, ok := aliases[final]
		if !ok {
			break
		}
		if !validRecordName(next) {
			return invalid(fmt.Errorf("dns: CNAME to %q", next))
		}
		final = next
	}
	if n != len(aliases) {
		return invalid(errors.New("dns: CNAME records do not form one chain"))
	}
	for _, r := range records {
		if r.name != final {
			return invalid(fmt.Errorf("dns: HTTPS record of %s, not %s", r.name, final))
		}
	}
	if len(records) == 0 {
		return noData(m, authority)
	}
	return services(records, host, port)
}

// noData returns the answer without HTTPS records, NXDOMAIN or NODATA:
// kept for the smallest TTL of the SOA records of the authority section,
// as Chrome caches the error, and not kept without one. The section stops
// at its first malformed record, as in Chrome.
func noData(m *message, authority int) HTTPS {
	var ttl uint32
	soa := false
	for range authority {
		r, ok := m.next()
		if !ok {
			break
		}
		if r.typ == uint16(dnsmessage.TypeSOA) && (!soa || r.ttl < ttl) {
			ttl, soa = r.ttl, true
		}
	}
	return HTTPS{Status: NoData, TTL: seconds(ttl)}
}

// services reads the records, all at the final name, as Chrome's
// ExtractHttpsResults: AliasMode records and incompatible ones give no
// service, and a ServiceMode record is used only when its target is the
// host or the owner of the record, its port, if any, is port, and it has
// a protocol.
func services(records []record, host string, port uint16) HTTPS {
	var out []Service
	var minTTL, minCompatible uint32
	compatible, alias, defaultALPN := false, false, false
	for _, r := range records {
		rd, _ := parseRecord(r.data) // checked by extract
		if rd.priority == 0 {
			alias = true
		} else if !rd.compatible() {
			continue
		}
		if !compatible || r.ttl < minCompatible {
			minCompatible = r.ttl
		}
		compatible = true
		if rd.priority == 0 {
			continue
		}
		target := rd.target
		if target == "" {
			target = r.name
		}
		if target != host && target != r.name {
			continue
		}
		if rd.hasPort && rd.port != port {
			continue
		}
		alpn := rd.alpn
		if rd.defaultALPN && !slices.Contains(alpn, "http/1.1") {
			alpn = append(alpn, "http/1.1")
		}
		if len(alpn) == 0 {
			continue
		}
		if len(out) == 0 || r.ttl < minTTL {
			minTTL = r.ttl
		}
		out = append(out, Service{Priority: rd.priority, ALPN: alpn, ECH: rd.ech})
		defaultALPN = defaultALPN || rd.defaultALPN
	}
	// An AliasMode record takes precedence over the others, and records
	// that all set no-default-alpn are not used (RFC 9460, Section 7.1.2).
	if alias || !defaultALPN {
		out = nil
	}
	switch {
	case len(out) > 0:
		slices.SortStableFunc(out, func(a, b Service) int { return int(a.Priority) - int(b.Priority) })
		return HTTPS{Status: Found, Services: out, TTL: seconds(minTTL)}
	case compatible:
		return HTTPS{Status: NoData, TTL: seconds(minCompatible)}
	default:
		return HTTPS{Status: Incompatible}
	}
}

func seconds(ttl uint32) time.Duration { return time.Duration(ttl) * time.Second }

// validRecordName reports a name Chrome accepts as the owner of a record
// (IsValidDnsRecordName): not localhost and not an IP address.
func validRecordName(name string) bool {
	if name == "" || name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return false
	}
	_, err := netip.ParseAddr(name)
	return err != nil
}

// rdata is an HTTPS record as Chrome's HttpsRecordRdata reads it.
type rdata struct {
	priority    uint16
	target      string // canonical; "" for "."
	mandatory   []uint16
	alpn        []string
	defaultALPN bool
	hasPort     bool
	port        uint16
	ech         []byte
}

// compatible reports whether every mandatory key is one Chrome supports.
func (r *rdata) compatible() bool {
	for _, k := range r.mandatory {
		if !supportedKey(k) {
			return false
		}
	}
	return true
}

// parseRecord reads the RDATA of an HTTPS record as Chrome does: the
// target name uncompressed, the keys in increasing order, each known key
// with a well-formed value. The params of an AliasMode record are only
// checked for their order and lengths.
func parseRecord(b []byte) (rdata, error) {
	errMalformed := errors.New("dns: malformed HTTPS record")
	r := rdata{defaultALPN: true}
	if len(b) < 2 {
		return r, errMalformed
	}
	r.priority = binary.BigEndian.Uint16(b)
	target, rest, ok := readTarget(b[2:])
	if !ok {
		return r, errMalformed
	}
	r.target = target
	last := -1
	for len(rest) > 0 {
		if len(rest) < 4 {
			return r, errMalformed
		}
		key, n := binary.BigEndian.Uint16(rest), int(binary.BigEndian.Uint16(rest[2:]))
		if int(key) <= last || len(rest) < 4+n {
			return r, errMalformed
		}
		last, rest = int(key), rest[4:]
		value := rest[:n]
		rest = rest[n:]
		if r.priority == 0 {
			continue
		}
		if err := r.setParam(key, value); err != nil {
			return r, err
		}
	}
	return r, nil
}

// setParam reads one SvcParam of a ServiceMode record.
func (r *rdata) setParam(key uint16, v []byte) error {
	errMalformed := fmt.Errorf("dns: malformed HTTPS key %d", key)
	switch key {
	case keyMandatory:
		if len(v) == 0 || len(v)%2 != 0 {
			return errMalformed
		}
		for i := 0; i < len(v); i += 2 {
			k := binary.BigEndian.Uint16(v[i:])
			// In increasing order, without mandatory itself.
			if k == keyMandatory || (len(r.mandatory) > 0 && k <= r.mandatory[len(r.mandatory)-1]) {
				return errMalformed
			}
			r.mandatory = append(r.mandatory, k)
		}
	case keyALPN:
		if len(v) == 0 {
			return errMalformed
		}
		for len(v) > 0 {
			n := int(v[0])
			if n == 0 || len(v) < 1+n {
				return errMalformed
			}
			r.alpn = append(r.alpn, string(v[1:1+n]))
			v = v[1+n:]
		}
	case keyNoDefaultALPN:
		if len(v) != 0 {
			return errMalformed
		}
		r.defaultALPN = false
	case keyPort:
		if len(v) != 2 {
			return errMalformed
		}
		r.hasPort, r.port = true, binary.BigEndian.Uint16(v)
	case keyIPv4Hint, keyIPv6Hint:
		size := 4
		if key == keyIPv6Hint {
			size = 16
		}
		if len(v) == 0 || len(v)%size != 0 {
			return errMalformed
		}
	case keyECH:
		r.ech = bytes.Clone(v)
	case keyTrustAnchors:
		if len(v) == 0 {
			return errMalformed
		}
		for len(v) > 0 {
			n := int(v[0])
			if n == 0 || len(v) < 1+n {
				return errMalformed
			}
			v = v[1+n:]
		}
	}
	return nil
}

// readTarget reads the target of an HTTPS record as Chrome does
// (NetworkToDottedName, require_complete): labels of 1 to 63 bytes up to
// the root, without compression, up to 255 bytes of labels and their
// lengths. The root alone is "".
func readTarget(b []byte) (string, []byte, bool) {
	var labels []string
	size := 0
	for {
		if len(b) == 0 {
			return "", nil, false
		}
		n := int(b[0])
		if n == 0 {
			return strings.ToLower(strings.Join(labels, ".")), b[1:], true
		}
		size += 1 + n
		if n > 63 || size > 255 || len(b) < 1+n {
			return "", nil, false
		}
		labels = append(labels, string(b[1:1+n]))
		b = b[1+n:]
	}
}
