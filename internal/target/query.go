package target

import "strings"

// EncodeQuery percent-encodes a raw query with the URL standard's
// special-query percent-encode set, as Chrome sends an http or https query:
// C0 controls, space, the double quote, '#', '<', '>', the apostrophe and
// bytes above '~'.
// Existing escapes are kept.
func EncodeQuery(raw string) string {
	const hex = "0123456789ABCDEF"
	var out []byte // nil until the first byte that needs encoding
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c > ' ' && c <= '~' && !strings.ContainsRune(`"#<>'`, rune(c)) {
			if out != nil {
				out = append(out, c)
			}
			continue
		}
		if out == nil {
			out = append(make([]byte, 0, len(raw)+8), raw[:i]...)
		}
		out = append(out, '%', hex[c>>4], hex[c&15])
	}
	if out == nil {
		return raw
	}
	return string(out)
}
