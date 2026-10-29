package http2

import "testing"

// altSvcValid accepts and refuses what quiche's ParseHeaderFieldValue
// does, with the values of its tests (spdy_alt_svc_wire_format_test.cc).
func TestAltSvcValid(t *testing.T) {
	for _, v := range []string{
		"clear",
		`h3=":443"; ma=86400, h3-29=":443"; ma=86400`,
		`h2="example.com:443"`,
		`quic=":443"; ma=2592000; v="46,43"`,
		`quic="[2003:8:0:16::509d:9615]:443"; v="36,35"; ma=60`,
		`hq=":443";quic=51303338;quic=51303334`,
		`hq=":443"; v=24`, // v is not a parameter of hq
		`a%25=":1"`,
		`a="b\"c:1"`,
		`a="b:042"; MA=7 ;  unknown=x  ,, b=":2"`,
		`a="b:42" ; `,
		`a="b:65535"; ma=4294967295`,
		`hq=":1";quic=51303A38`,
		`A%2f%2F=":1"`,
	} {
		if !altSvcValid([]byte(v)) {
			t.Errorf("%q refused", v)
		}
	}
	for _, v := range []string{
		"",
		"a%", "a%x", "a%b", "a%9z", "a=", `a="`, `a="b"`, `a=":"`, `a="c:"`,
		`a="c:foo"`, `a="c:42foo"`, `a="b:42"bar`, `a="b:42" ; m`,
		`a="b:42" ; min-age`, `a="b:42" ; ma`, `a="b:42" ; ma=`,
		`a="b:42" ; v=".."`, `a="b:42" ; ma=ma`, `a="b:42" ; ma=123bar`,
		`a="b:42" ; v=24`, `a="b:42" ; v=24,25`, `a="b:42" ; v="-3"`,
		`a="b:42" ; v="1.2"`, `a="b:42" ; v="24,"`,
		// Others: an empty protocol, port 0 or above 65535, ma above
		// 2^32-1, a bracket not closed, a quote in brackets, a quic tag
		// with a leading zero, of value 0 or over 8 digits, an escape at
		// the end, an unclosed version list.
		`=":1"`, `a=":0"`, `a=":65536"`, `a=":1"; ma=4294967296`, `a="[::1:1"`,
		`a="[\"]:1"`, `hq=":1";quic=051`, `hq=":1";quic=0`, `hq=":1";quic=123456789`,
		`hq=":1";quic=5x`, `a="b\`, `a=":1"; v="1`, `a=":1"; v=""`, "a=\":1\"\x00",
		`a=""`, `a=x:1"`, `a=":1"; x y=1`, `a=":1"; x=`, `a=":1"; v=x5"`, `a=":1"; v="65536"`,
		`a=":1"; MA=x`, `a="[::1]x1"`, "a=\":1\",\t=\":2\"", `a%x=":1"`, `a%2x=":1"`, `a%x2=":1"`,
	} {
		if altSvcValid([]byte(v)) {
			t.Errorf("%q accepted", v)
		}
	}
	// A value cut before its closing quote is refused at every length.
	for _, v := range []string{`a=":137"`, `a="foo:137"`, `a%25="foo\"bar\\baz:137"`} {
		for n := 1; n < len(v); n++ {
			if altSvcValid([]byte(v[:n])) {
				t.Errorf("%q accepted", v[:n])
			}
		}
	}
}
