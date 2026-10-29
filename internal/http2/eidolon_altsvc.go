// The Alt-Svc value of an ALTSVC frame as quiche checks it (patch 0037).

package http2

import "bytes"

// altSvcValid reports whether quiche's
// SpdyAltSvcWireFormat::ParseHeaderFieldValue accepts v, the field value of
// an ALTSVC frame; Http2DecoderAdapter::OnAltSvcEnd reports
// SPDY_INVALID_CONTROL_FRAME otherwise. It follows the parser step by step,
// quirks included, and keeps nothing it parses; the checks of the parser
// that a later one covers are left out.
func altSvcValid(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	if string(v) == "clear" {
		return true
	}
	end := len(v)
	c := 0
	for c != end {
		// protocol-id, percent-encoded
		eq := indexFrom(v, c, '=')
		protocolID, ok := altSvcPercentDecode(v[c:eq])
		if eq == c || !ok {
			return false
		}
		ietfQUIC := protocolID == "hq"
		c = eq
		if c == end {
			return false
		}
		c++
		// alt-authority, quoted, with backslash escapes
		if c == end || v[c] != '"' {
			return false
		}
		c++
		authority := c
		for ; c != end && v[c] != '"'; c++ {
			if v[c] != '\\' {
				continue
			}
			c++
			if c == end {
				return false
			}
		}
		if c == end || !altSvcAuthorityValid(v[authority:c]) {
			return false
		}
		c++
		// parameters, up to the next comma
		paramsEnd := indexFrom(v, c, ',')
		for c != paramsEnd {
			c = skipWhiteSpace(v, c, paramsEnd)
			if c == paramsEnd {
				break
			}
			if v[c] != ';' {
				return false
			}
			c++
			c = skipWhiteSpace(v, c, paramsEnd)
			if c == paramsEnd {
				break
			}
			var name []byte
			for ; c != paramsEnd && v[c] != '=' && v[c] != ' ' && v[c] != '\t'; c++ {
				name = append(name, asciiLower(v[c]))
			}
			c = skipWhiteSpace(v, c, paramsEnd)
			if c == paramsEnd || v[c] != '=' {
				return false
			}
			c++
			c = skipWhiteSpace(v, c, paramsEnd)
			value := c
			for ; c != paramsEnd && v[c] != ';' && v[c] != ' ' && v[c] != '\t'; c++ {
			}
			if c == value {
				return false
			}
			switch {
			case string(name) == "ma":
				if !altSvcPositive(v[value:c], 1<<32-1) {
					return false
				}
			case !ietfQUIC && string(name) == "v":
				// A quoted list of versions, which may hold commas: the
				// end of the parameters moves past it.
				if v[value] != '"' {
					return false
				}
				c = indexFrom(v, value+1, '"')
				if c == end {
					return false
				}
				c++
				paramsEnd = indexFrom(v, c, ',')
				for vb := value + 1; vb < c; {
					ve := vb
					for ve < c-1 && v[ve] != ',' {
						ve++
					}
					if !altSvcPositive(v[vb:ve], 1<<16-1) {
						return false
					}
					vb = ve + 1
				}
			case ietfQUIC && string(name) == "quic":
				// A QUIC version tag in hex, without leading zeros,
				// which also leaves out 0.
				if v[value] == '0' || !altSvcHex32(v[value:c]) {
					return false
				}
			}
		}
		for ; c != end && (v[c] == ' ' || v[c] == '\t' || v[c] == ','); c++ {
		}
	}
	return true
}

// indexFrom returns the index of the first b in v from i, or len(v).
func indexFrom(v []byte, i int, b byte) int {
	if j := bytes.IndexByte(v[i:], b); j >= 0 {
		return i + j
	}
	return len(v)
}

// skipWhiteSpace returns the index of the first byte from c to end that is
// neither a space nor a tab, or end.
func skipWhiteSpace(v []byte, c, end int) int {
	for c != end && (v[c] == ' ' || v[c] == '\t') {
		c++
	}
	return c
}

func asciiLower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

func hexDigit(b byte) (byte, bool) {
	switch {
	case '0' <= b && b <= '9':
		return b - '0', true
	case 'a' <= b && b <= 'f':
		return b - 'a' + 10, true
	case 'A' <= b && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// altSvcPercentDecode decodes the %XX escapes of s, as PercentDecode.
func altSvcPercentDecode(s []byte) (string, bool) {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		hi, ok1 := hexDigit(s[i+1])
		lo, ok2 := hexDigit(s[i+2])
		if !ok1 || !ok2 {
			return "", false
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return string(out), true
}

// altSvcAuthorityValid reports whether ParseAltAuthority accepts a: an
// optional host, a bracketed IPv6 literal or a name with backslash
// escapes, then a colon and a port from 1 to 65535.
func altSvcAuthorityValid(a []byte) bool {
	if len(a) == 0 {
		return false
	}
	c, end := 0, len(a)
	if a[c] == '[' {
		for ; c != end && a[c] != ']'; c++ {
			if a[c] == '"' {
				return false
			}
		}
		if c == end {
			return false
		}
		c++
	} else {
		for ; c != end && a[c] != ':'; c++ {
			if a[c] == '"' {
				return false
			}
			if a[c] == '\\' {
				c++
				if c == end {
					return false
				}
			}
		}
	}
	if c == end || a[c] != ':' {
		return false
	}
	return altSvcPositive(a[c+1:], 1<<16-1)
}

// altSvcPositive reports whether s is a decimal integer from 1 to max, as
// ParsePositiveIntegerImpl.
func altSvcPositive(s []byte, max uint64) bool {
	var n uint64
	for _, b := range s {
		if b < '0' || b > '9' {
			return false
		}
		if n = n*10 + uint64(b-'0'); n > max {
			return false
		}
	}
	return n > 0
}

// altSvcHex32 reports whether s, not empty, is up to 8 hex digits, as
// HexDecodeToUInt32 accepts.
func altSvcHex32(s []byte) bool {
	if len(s) > 8 {
		return false
	}
	for _, b := range s {
		if _, ok := hexDigit(b); !ok {
			return false
		}
	}
	return true
}
