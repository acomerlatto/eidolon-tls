package dns

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// rr is a record of a test response.
type rr struct {
	name  string
	typ   dnsmessage.Type
	class dnsmessage.Class // 0: IN
	ttl   uint32
	data  []byte
}

// response returns the response to query with rcode, the answers and the
// authority records.
func response(t *testing.T, query []byte, rcode dnsmessage.RCode, answers, authority []rr) []byte {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		t.Fatal(err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true, RCode: rcode})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(b.StartQuestions())
	must(b.Question(q))
	add := func(r rr) {
		t.Helper()
		class := r.class
		if class == 0 {
			class = dnsmessage.ClassINET
		}
		h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(r.name + "."), Type: r.typ, Class: class, TTL: r.ttl}
		must(b.UnknownResource(h, dnsmessage.UnknownResource{Type: r.typ, Data: r.data}))
	}
	must(b.StartAnswers())
	for _, r := range answers {
		add(r)
	}
	must(b.StartAuthorities())
	for _, r := range authority {
		add(r)
	}
	msg, err := b.Finish()
	must(err)
	return msg
}

// name returns the wire form of a name.
func name(n string) []byte {
	var b []byte
	if n != "" {
		for _, l := range strings.Split(n, ".") {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
	}
	return append(b, 0)
}

// param is a SvcParam.
type param struct {
	key   uint16
	value []byte
}

// svc returns the RDATA of an HTTPS record.
func svc(priority uint16, target string, params ...param) []byte {
	b := binary.BigEndian.AppendUint16(nil, priority)
	b = append(b, name(target)...)
	for _, p := range params {
		b = binary.BigEndian.AppendUint16(b, p.key)
		b = binary.BigEndian.AppendUint16(b, uint16(len(p.value)))
		b = append(b, p.value...)
	}
	return b
}

func alpn(ids ...string) param {
	var v []byte
	for _, id := range ids {
		v = append(v, byte(len(id)))
		v = append(v, id...)
	}
	return param{keyALPN, v}
}

func keys(ks ...uint16) []byte {
	var v []byte
	for _, k := range ks {
		v = binary.BigEndian.AppendUint16(v, k)
	}
	return v
}

var (
	noDefault = param{keyNoDefaultALPN, nil}
	ech1      = param{keyECH, []byte("ech-1")}
	ech2      = param{keyECH, []byte("ech-2")}
)

func port(p uint16) param { return param{keyPort, binary.BigEndian.AppendUint16(nil, p)} }

func https(name string, ttl uint32, data []byte) rr {
	return rr{name: name, typ: TypeHTTPS, ttl: ttl, data: data}
}

func cname(owner, target string, ttl uint32) rr {
	return rr{name: owner, typ: dnsmessage.TypeCNAME, ttl: ttl, data: name(target)}
}

func soa(name string, ttl uint32) rr {
	data := append(append(name2("ns."+name), name2("admin."+name)...), make([]byte, 20)...)
	return rr{name: name, typ: dnsmessage.TypeSOA, ttl: ttl, data: data}
}

func name2(n string) []byte { return name(n) }

func query(t *testing.T, n string) []byte {
	t.Helper()
	q, err := Query(0x1234, n, TypeHTTPS, false)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// Query writes Chrome's DnsQuery: ID, RD, one question and, padded for
// DoH, an OPT record whose padding option fills a block of 128 bytes.
func TestQuery(t *testing.T) {
	q, err := Query(0xabcd, "Example.com", TypeHTTPS, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	want = append(want, name("Example.com")...)
	want = append(want, 0, 65, 0, 1)
	if !bytes.Equal(q, want) {
		t.Errorf("query\n%x, want\n%x", q, want)
	}
	// 12 + name + 4 + 11 + 4: names of 98 and 97 bytes on the wire fill
	// the block exactly and with one byte to spare.
	for _, n := range []string{"example.com", strings.Repeat("a", 63) + "." + strings.Repeat("b", 32), strings.Repeat("a", 63) + "." + strings.Repeat("b", 31)} {
		q, err := Query(0, n, TypeHTTPS, true)
		if err != nil {
			t.Fatal(err)
		}
		if want := (12 + len(name(n)) + 4 + 11 + 4 + 127) / 128 * 128; len(q) != want {
			t.Errorf("%s: padded query of %d bytes, want %d", n, len(q), want)
		}
		if binary.BigEndian.Uint16(q[10:]) != 1 {
			t.Errorf("%s: ARCOUNT %d", n, binary.BigEndian.Uint16(q[10:]))
		}
		opt := q[12+len(name(n))+4:]
		head := []byte{0, 0, 41, 0x10, 0, 0, 0, 0, 0}
		if !bytes.Equal(opt[:9], head) {
			t.Errorf("%s: OPT record %x, want %x", n, opt[:9], head)
		}
		if binary.BigEndian.Uint16(opt[9:]) != uint16(len(opt)-11) || binary.BigEndian.Uint16(opt[11:]) != 12 ||
			binary.BigEndian.Uint16(opt[13:]) != uint16(len(opt)-15) || !bytes.Equal(opt[15:], make([]byte, len(opt)-15)) {
			t.Errorf("%s: OPT %x", n, opt)
		}
	}
	for _, n := range []string{"", "example.com.", strings.Repeat("a", 64) + ".com"} {
		if _, err := Query(0, n, TypeHTTPS, false); err == nil {
			t.Errorf("%q: no error", n)
		}
	}
}

// A response that does not answer the query, or a SERVFAIL, fails; the
// other error codes are refusals; NXDOMAIN is an answer.
func TestParseResponse(t *testing.T) {
	q := query(t, "example.com")
	ok := response(t, q, dnsmessage.RCodeSuccess, []rr{https("example.com", 60, svc(1, "", ech1))}, nil)
	if got := Parse(q, ok, "example.com", 443); got.Status != Found {
		t.Fatalf("valid response: %v %v", got.Status, got.Err)
	}
	edit := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(ok)) }
	upper := query(t, "Example.com")
	for name, resp := range map[string][]byte{
		"short":           ok[:11],
		"other ID":        edit(func(b []byte) []byte { b[1]++; return b }),
		"not a response":  edit(func(b []byte) []byte { b[2] &^= 0x80; return b }),
		"two questions":   edit(func(b []byte) []byte { b[5] = 2; return b }),
		"other case":      response(t, upper, dnsmessage.RCodeSuccess, nil, nil),
		"other type":      edit(func(b []byte) []byte { b[12+13+1] = 1; return b }),
		"no question":     ok[:12+13+3],
		"SERVFAIL":        response(t, q, dnsmessage.RCodeServerFailure, nil, nil),
		"bad name in rr":  edit(func(b []byte) []byte { b[12+17] = 0xc0; b[12+18] = 0xff; return b }),
		"truncated rdata": ok[:len(ok)-1],
	} {
		got := Parse(q, resp, "example.com", 443)
		want := Failed
		if strings.HasPrefix(name, "bad") || strings.HasPrefix(name, "truncated") {
			want = Invalid
		}
		if got.Status != want || got.Err == nil {
			t.Errorf("%s: %v %v, want %v", name, got.Status, got.Err, want)
		}
	}
	for _, rc := range []dnsmessage.RCode{dnsmessage.RCodeFormatError, dnsmessage.RCodeNotImplemented, dnsmessage.RCodeRefused, 9, 10} {
		if got := Parse(q, response(t, q, rc, nil, nil), "example.com", 443); got.Status != Refused || got.Err == nil {
			t.Errorf("%v: %v %v", rc, got.Status, got.Err)
		}
	}
	nx := response(t, q, dnsmessage.RCodeNameError, nil, []rr{soa("example.com", 300), soa("com", 60), {name: "com", typ: dnsmessage.TypeNS, ttl: 1, data: name("ns.com")}})
	if got := Parse(q, nx, "example.com", 443); got.Status != NoData || got.TTL != 60*time.Second || got.Err != nil {
		t.Errorf("NXDOMAIN: %+v", got)
	}
	nodata := response(t, q, dnsmessage.RCodeSuccess, nil, nil)
	if got := Parse(q, nodata, "example.com", 443); got.Status != NoData || got.TTL != 0 {
		t.Errorf("NODATA without SOA: %+v", got)
	}
	// The authority section stops at its first malformed record.
	broken := response(t, q, dnsmessage.RCodeSuccess, nil, []rr{soa("example.com", 300), soa("com", 60)})
	broken = broken[:len(broken)-1]
	if got := Parse(q, broken, "example.com", 443); got.Status != NoData || got.TTL != 300*time.Second {
		t.Errorf("malformed authority: %+v", got)
	}
	// NXDOMAIN with records keeps them.
	nxrr := response(t, q, dnsmessage.RCodeNameError, []rr{https("example.com", 60, svc(1, ""))}, nil)
	if got := Parse(q, nxrr, "example.com", 443); got.Status != Found {
		t.Errorf("NXDOMAIN with records: %+v", got)
	}
	// A query that cannot be read.
	if got := Parse(q[:11], ok, "example.com", 443); got.Status != Failed {
		t.Errorf("short query: %+v", got)
	}
	if got := Parse(q[:14], ok, "example.com", 443); got.Status != Failed {
		t.Errorf("query without question: %+v", got)
	}
	if got := Parse(q[:12+13+2], ok, "example.com", 443); got.Status != Failed {
		t.Errorf("query without class: %+v", got)
	}
	// A record whose header is cut short.
	if got := Parse(q, ok[:12+17+13+9], "example.com", 443); got.Status != Invalid {
		t.Errorf("short record header: %+v", got)
	}
	// Only the authority section gives the TTL of NXDOMAIN.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, Response: true, RCode: dnsmessage.RCodeNameError})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: TypeHTTPS, Class: dnsmessage.ClassINET})
	b.StartAdditionals()
	r := soa("example.com", 300)
	b.UnknownResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.com."), Type: r.typ, Class: dnsmessage.ClassINET, TTL: r.ttl}, dnsmessage.UnknownResource{Type: r.typ, Data: r.data})
	additional, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if got := Parse(q, additional, "example.com", 443); got.Status != NoData || got.TTL != 0 {
		t.Errorf("SOA in the additional section: %+v", got)
	}
}

// The services are those of ExtractHttpsResults.
func TestServices(t *testing.T) {
	const h = "example.com"
	tests := []struct {
		name     string
		host     string
		port     uint16
		records  []rr
		status   Status
		services []Service
		ttl      time.Duration
	}{
		{"one", h, 443, []rr{https(h, 60, svc(1, "", ech1))},
			Found, []Service{{1, []string{"http/1.1"}, []byte("ech-1")}}, time.Minute},
		{"alpn keeps the default", h, 443, []rr{https(h, 60, svc(1, "", alpn("h3", "h2")))},
			Found, []Service{{1, []string{"h3", "h2", "http/1.1"}, nil}}, time.Minute},
		{"http/1.1 listed once", h, 443, []rr{https(h, 60, svc(1, "", alpn("http/1.1", "h2")))},
			Found, []Service{{1, []string{"http/1.1", "h2"}, nil}}, time.Minute},
		{"by priority, stable", h, 443, []rr{
			https(h, 50, svc(2, "", ech1)), https(h, 40, svc(1, "", alpn("h2"), noDefault)), https(h, 30, svc(2, "", ech2)),
		}, Found, []Service{
			{1, []string{"h2"}, nil}, {2, []string{"http/1.1"}, []byte("ech-1")}, {2, []string{"http/1.1"}, []byte("ech-2")},
		}, 30 * time.Second},
		{"all no-default-alpn", h, 443, []rr{https(h, 60, svc(1, "", alpn("h2"), noDefault))},
			NoData, nil, time.Minute},
		{"no protocol", h, 443, []rr{https(h, 60, svc(1, "", noDefault)), https(h, 70, svc(2, ""))},
			Found, []Service{{2, []string{"http/1.1"}, nil}}, 70 * time.Second},
		{"alias wins", h, 443, []rr{https(h, 60, svc(1, "", ech1)), https(h, 20, svc(0, "cdn.example.net"))},
			NoData, nil, 20 * time.Second},
		{"alias only", h, 443, []rr{https(h, 90, svc(0, "cdn.example.net"))}, NoData, nil, 90 * time.Second},
		{"incompatible", h, 443, []rr{https(h, 60, svc(1, "", param{keyMandatory, keys(7)}, param{7, nil}))},
			Incompatible, nil, 0},
		{"incompatible skipped", h, 443, []rr{
			https(h, 10, svc(1, "", param{keyMandatory, keys(keyALPN, 8)}, alpn("h2"))), https(h, 60, svc(2, "", param{keyMandatory, keys(keyALPN, keyECH, keyTrustAnchors)}, alpn("h2"), ech1, param{keyTrustAnchors, []byte{1, 9}})),
		}, Found, []Service{{2, []string{"h2", "http/1.1"}, []byte("ech-1")}}, time.Minute},
		{"other target", h, 443, []rr{https(h, 60, svc(1, "cdn.example.net", ech1))}, NoData, nil, time.Minute},
		{"target is the host", h, 443, []rr{https(h, 60, svc(1, "EXAMPLE.com", ech1))},
			Found, []Service{{1, []string{"http/1.1"}, []byte("ech-1")}}, time.Minute},
		{"other port", h, 443, []rr{https(h, 60, svc(1, "", port(8443))), https(h, 70, svc(2, "", port(443)))},
			Found, []Service{{2, []string{"http/1.1"}, nil}}, 70 * time.Second},
		{"TTL of the services", h, 443, []rr{https(h, 5, svc(1, "", port(1))), https(h, 70, svc(2, ""))},
			Found, []Service{{2, []string{"http/1.1"}, nil}}, 70 * time.Second},
		{"compatible TTL", h, 443, []rr{https(h, 50, svc(1, "", port(1))), https(h, 40, svc(1, "x.test")), https(h, 5, svc(1, "", param{keyMandatory, keys(9)}))},
			NoData, nil, 40 * time.Second},
		{"mandatory ipv6hint", h, 443, []rr{https(h, 60, svc(1, "", param{keyMandatory, keys(keyIPv6Hint)}, param{keyIPv6Hint, make([]byte, 16)}))},
			Found, []Service{{1, []string{"http/1.1"}, nil}}, time.Minute},
		{"hints", h, 443, []rr{https(h, 60, svc(1, "", param{keyIPv4Hint, []byte{1, 2, 3, 4, 5, 6, 7, 8}}, param{keyIPv6Hint, make([]byte, 16)}))},
			Found, []Service{{1, []string{"http/1.1"}, nil}}, time.Minute},
		{"unknown keys", h, 443, []rr{https(h, 60, svc(1, "", alpn("h2"), param{7, []byte("/q{?dns}")}, param{9, nil}, param{14, []byte{1}}, param{65535, nil}))},
			Found, []Service{{1, []string{"h2", "http/1.1"}, nil}}, time.Minute},
		{"other class", h, 443, []rr{{name: h, typ: TypeHTTPS, class: dnsmessage.ClassCHAOS, ttl: 1, data: svc(1, "", ech2)}, {name: h, typ: dnsmessage.TypeCNAME, class: dnsmessage.ClassCHAOS, ttl: 1, data: name("x.test")}, https(h, 60, svc(1, ""))},
			Found, []Service{{1, []string{"http/1.1"}, nil}}, time.Minute},
		{"other types", h, 443, []rr{{name: h, typ: dnsmessage.TypeA, ttl: 1, data: []byte{1, 2, 3, 4}}, {name: h, typ: dnsmessage.TypeAAAA, ttl: 1, data: make([]byte, 16)}, {name: h, typ: dnsmessage.TypeTXT, ttl: 1, data: []byte{0}}, https(h, 60, svc(1, ""))},
			Found, []Service{{1, []string{"http/1.1"}, nil}}, time.Minute},
		{"CNAME chain", h, 443, []rr{cname(h, "a.example.net", 9), cname("a.example.net", "B.example.net", 9), https("b.example.net", 60, svc(1, "", ech1)), https("b.example.net", 60, svc(2, h)), https("b.example.net", 60, svc(3, "a.example.net"))},
			Found, []Service{{1, []string{"http/1.1"}, []byte("ech-1")}, {2, []string{"http/1.1"}, nil}}, time.Minute},
		{"port name", "example.com", 8443, []rr{https("_8443._https.example.com", 60, svc(1, "")), https("_8443._https.example.com", 60, svc(2, h, port(8443)))},
			Found, []Service{{1, []string{"http/1.1"}, nil}, {2, []string{"http/1.1"}, nil}}, time.Minute},
	}
	for _, tt := range tests {
		qname := tt.host
		if tt.port != 443 {
			qname = "_8443._https." + qname
		}
		q := query(t, qname)
		got := Parse(q, response(t, q, dnsmessage.RCodeSuccess, tt.records, nil), tt.host, tt.port)
		if got.Status != tt.status || !reflect.DeepEqual(got.Services, tt.services) || got.TTL != tt.ttl || got.Err != nil {
			t.Errorf("%s: %v %+v %v %v\nwant %v %+v %v", tt.name, got.Status, got.Services, got.TTL, got.Err, tt.status, tt.services, tt.ttl)
		}
	}
}

// Answers whose records Chrome cannot read, or that do not form one chain
// of CNAMEs to the HTTPS records, are invalid.
func TestInvalidAnswers(t *testing.T) {
	const h = "example.com"
	long := strings.Repeat("a", 63)
	tests := map[string][]rr{
		"no target":               {https(h, 1, []byte{0, 1})},
		"short":                   {https(h, 1, []byte{0})},
		"compressed target":       {https(h, 1, []byte{0, 1, 0xc0, 12})},
		"label of 64":             {https(h, 1, append([]byte{0, 1, 64}, make([]byte, 65)...))},
		"name of 256":             {https(h, 1, svc(1, long+"."+long+"."+long+"."+long))},
		"target without root":     {https(h, 1, []byte{0, 1, 1, 'a'})},
		"keys out of order":       {https(h, 1, svc(1, "", alpn("h2"), param{keyMandatory, keys(keyALPN)}))},
		"key twice":               {https(h, 1, svc(1, "", alpn("h2"), alpn("h3")))},
		"short key":               {https(h, 1, append(svc(1, ""), 0, 1, 0))},
		"short value":             {https(h, 1, append(svc(1, ""), 0, 1, 0, 3, 2, 'h'))},
		"empty mandatory":         {https(h, 1, svc(1, "", param{keyMandatory, nil}))},
		"odd mandatory":           {https(h, 1, svc(1, "", param{keyMandatory, []byte{0, 1, 0}}))},
		"mandatory lists itself":  {https(h, 1, svc(1, "", param{keyMandatory, keys(0, 1)}, alpn("h2")))},
		"mandatory out of order":  {https(h, 1, svc(1, "", param{keyMandatory, keys(5, 1)}, alpn("h2"), ech1))},
		"mandatory twice":         {https(h, 1, svc(1, "", param{keyMandatory, keys(1, 1)}, alpn("h2")))},
		"empty alpn":              {https(h, 1, svc(1, "", param{keyALPN, nil}))},
		"empty alpn id":           {https(h, 1, svc(1, "", param{keyALPN, []byte{2, 'h', '2', 0}}))},
		"short alpn id":           {https(h, 1, svc(1, "", param{keyALPN, []byte{3, 'h', '2'}}))},
		"no-default-alpn value":   {https(h, 1, svc(1, "", alpn("h2"), param{keyNoDefaultALPN, []byte{0}}))},
		"short port":              {https(h, 1, svc(1, "", param{keyPort, []byte{1}}))},
		"long port":               {https(h, 1, svc(1, "", param{keyPort, []byte{0, 1, 2}}))},
		"empty ipv4hint":          {https(h, 1, svc(1, "", param{keyIPv4Hint, nil}))},
		"ipv4hint of 5":           {https(h, 1, svc(1, "", param{keyIPv4Hint, make([]byte, 5)}))},
		"ipv6hint of 15":          {https(h, 1, svc(1, "", param{keyIPv6Hint, make([]byte, 15)}))},
		"empty trust anchors":     {https(h, 1, svc(1, "", param{keyTrustAnchors, nil}))},
		"empty trust anchor":      {https(h, 1, svc(1, "", param{keyTrustAnchors, []byte{1, 7, 0}}))},
		"short trust anchor":      {https(h, 1, svc(1, "", param{keyTrustAnchors, []byte{2, 7}}))},
		"alias keys out of order": {https(h, 1, svc(0, "a.test", param{3, nil}, param{1, nil}))},
		"short A":                 {{name: h, typ: dnsmessage.TypeA, ttl: 1, data: []byte{1, 2, 3}}, https(h, 1, svc(1, ""))},
		"long AAAA":               {{name: h, typ: dnsmessage.TypeAAAA, ttl: 1, data: make([]byte, 17)}, https(h, 1, svc(1, ""))},
		"bad CNAME":               {{name: h, typ: dnsmessage.TypeCNAME, ttl: 1, data: []byte{1}}},
		"two CNAMEs":              {cname(h, "a.test", 1), cname(h, "a.test", 1), https("a.test", 1, svc(1, ""))},
		"CNAME to an IP address":  {cname(h, "10.0.0.1", 1)},
		"other class, bad record": {{name: h, typ: TypeHTTPS, class: dnsmessage.ClassCHAOS, ttl: 1, data: []byte{0, 1}}, https(h, 1, svc(1, ""))},
		"other class, bad A":      {{name: h, typ: dnsmessage.TypeA, class: dnsmessage.ClassCHAOS, ttl: 1, data: []byte{1}}, https(h, 1, svc(1, ""))},
		"short AAAA":              {{name: h, typ: dnsmessage.TypeAAAA, ttl: 1, data: make([]byte, 15)}, https(h, 1, svc(1, ""))},
		"A of localhost":          {{name: "localhost", typ: dnsmessage.TypeA, ttl: 1, data: make([]byte, 4)}, https(h, 1, svc(1, ""))},
		"A of a.localhost":        {{name: "a.localhost", typ: dnsmessage.TypeA, ttl: 1, data: make([]byte, 4)}, https(h, 1, svc(1, ""))},
		"A of an IP address":      {{name: "10.1.2.3", typ: dnsmessage.TypeA, ttl: 1, data: make([]byte, 4)}, https(h, 1, svc(1, ""))},
		"A of the root":           {{name: "", typ: dnsmessage.TypeA, ttl: 1, data: make([]byte, 4)}, https(h, 1, svc(1, ""))},
		"ipv6hint of 8":           {https(h, 1, svc(1, "", param{keyIPv6Hint, make([]byte, 8)}))},
		"CNAME loop":              {cname(h, "a.test", 1), cname("a.test", h, 1)},
		"CNAME off the chain":     {cname("x.test", "a.test", 1), https(h, 1, svc(1, ""))},
		"record off the chain":    {cname(h, "a.test", 1), https(h, 1, svc(1, ""))},
		"record of another name":  {https("other.test", 1, svc(1, ""))},
		"record of localhost":     {https("localhost", 1, svc(1, ""))},
		"record of a.localhost":   {https("a.localhost", 1, svc(1, ""))},
		"record of an IP address": {https("127.0.0.1", 1, svc(1, ""))},
		"record of an IPv6 owner": {{name: "::1", typ: TypeHTTPS, ttl: 1, data: svc(1, "")}},
	}
	for name, records := range tests {
		q := query(t, h)
		got := Parse(q, response(t, q, dnsmessage.RCodeSuccess, records, nil), h, 443)
		if got.Status != Invalid || got.Err == nil {
			t.Errorf("%s: %v %+v", name, got.Status, got)
		}
	}
	// AliasMode params are only checked for order and lengths.
	q := query(t, h)
	alias := https(h, 7, svc(0, "a.test", param{keyALPN, nil}, param{keyPort, []byte{1}}))
	if got := Parse(q, response(t, q, dnsmessage.RCodeSuccess, []rr{alias}, nil), h, 443); got.Status != NoData || got.TTL != 7*time.Second {
		t.Errorf("alias params: %+v", got)
	}
}

func TestStatusString(t *testing.T) {
	for s, want := range map[Status]string{Found: "found", NoData: "no data", Incompatible: "incompatible", Invalid: "invalid", Refused: "refused", Failed: "failed", 9: "Status(9)"} {
		if s.String() != want {
			t.Errorf("%d: %q, want %q", s, s.String(), want)
		}
	}
}

// readName follows DnsRecordParser::ReadName: compression pointers
// anywhere in the message, loops and long names refused.
func TestReadName(t *testing.T) {
	msg := append([]byte{0xff}, name("a.example")...) // 1..11
	msg = append(msg, 1, 'b', 0xc0, 3)                // 12: b + pointer to example
	msg = append(msg, 0xc0, 12)                       // 16: pointer to b.example
	msg = append(msg, 0xc0, 18)                       // 18: pointer to itself
	msg = append(msg, 0x40, 0, 0x80, 0)               // 20, 22: unknown label types
	msg = append(msg, 0xc0, 0xff)                     // 24: pointer out of the message
	for _, tt := range []struct {
		off      int
		name     string
		consumed int
		ok       bool
	}{
		{1, "a.example", 11, true},
		{12, "b.example", 4, true},
		{16, "b.example", 2, true},
		{18, "", 0, false},
		{20, "", 0, false},
		{22, "", 0, false},
		{24, "", 0, false},
		{len(msg), "", 0, false},
		{len(msg) - 1, "", 0, false}, // a pointer cut short
	} {
		got, n, ok := readName(msg, tt.off)
		if got != tt.name || n != tt.consumed || ok != tt.ok {
			t.Errorf("at %d: %q %d %v, want %q %d %v", tt.off, got, n, ok, tt.name, tt.consumed, tt.ok)
		}
	}
	// A label that reaches the end of the message, without the root.
	if _, _, ok := readName([]byte{1, 'a'}, 0); ok {
		t.Error("label at the end: accepted")
	}
	if _, _, ok := readName([]byte{1, 'a', 0}, 0); !ok {
		t.Error("a.: refused")
	}
	// 255 bytes of labels, lengths included and the root not, are
	// accepted, 256 are not, also through pointers.
	label := append([]byte{63}, bytes.Repeat([]byte{'x'}, 63)...)
	for size, want := range map[int]bool{255: true, 256: false} {
		var b []byte
		for range 3 {
			b = append(b, label...)
		}
		rest := size - 3*64 // after three labels of 64
		b = append(b, byte(rest-1))
		b = append(b, bytes.Repeat([]byte{'y'}, rest-1)...)
		b = append(b, 0)
		if _, _, ok := readName(b, 0); ok != want {
			t.Errorf("name of %d bytes: %v", size, ok)
		}
		split := append(append(b[3*64:len(b):len(b)], b[:3*64]...), 0xc0, 0)
		if _, _, ok := readName(split, len(b)-3*64); ok != want {
			t.Errorf("name of %d bytes through a pointer: %v", size, ok)
		}
	}
}

// Names of the answer may be compressed, CNAME targets included.
func TestCompressedAnswer(t *testing.T) {
	q := query(t, "example.com")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, Response: true})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: TypeHTTPS, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	b.CNAMEResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.com."), Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("cdn.example.com.")})
	b.UnknownResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("cdn.example.com."), Type: TypeHTTPS, Class: dnsmessage.ClassINET, TTL: 9}, dnsmessage.UnknownResource{Type: TypeHTTPS, Data: svc(1, "", ech1)})
	resp, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(resp[len(q):], []byte{0xc0}) {
		t.Fatal("the answer is not compressed")
	}
	got := Parse(q, resp, "example.com", 443)
	if got.Status != Found || len(got.Services) != 1 || got.TTL != 9*time.Second {
		t.Errorf("%+v", got)
	}
}

// Services of one priority keep the order of the answer, however many.
func TestServicesStable(t *testing.T) {
	const h = "example.com"
	var records []rr
	var want []Service
	for i := range 40 {
		ech := []byte{byte(i)}
		records = append(records, https(h, 60, svc(uint16(2-i%2), "", param{keyECH, ech})))
		if i%2 == 1 {
			want = append(want, Service{1, []string{"http/1.1"}, ech})
		}
	}
	for i := 0; i < 40; i += 2 {
		want = append(want, Service{2, []string{"http/1.1"}, []byte{byte(i)}})
	}
	q := query(t, h)
	got := Parse(q, response(t, q, dnsmessage.RCodeSuccess, records, nil), h, 443)
	if !reflect.DeepEqual(got.Services, want) {
		t.Errorf("services out of order:\n%v\nwant\n%v", got.Services, want)
	}
}
