package eidolon

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// akamaiPseudo maps the letters of the pseudo-header part of an Akamai
// fingerprint to the pseudo-header fields of a request.
var akamaiPseudo = map[string]string{"m": ":method", "a": ":authority", "s": ":scheme", "p": ":path"}

// Akamai returns the Akamai fingerprint of the start of an HTTP/2
// connection with s and the pseudo-header order pseudo, as the tracker of
// peet.ws (TrackMe) writes it: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO.
// SETTINGS are id:value in order, joined with ";"; WINDOW_UPDATE is the
// connection increment, "00" for none; PRIORITY lists the PRIORITY frames
// as stream:exclusive:dependency:weight, with the weight from 1 to 256,
// joined with ",", or "0" for none; PSEUDO is the second letter of each
// pseudo-header field, joined with ",". The priority of HEADERS and the
// other fields of s are not part of it.
//
// The Chrome 156 profile gives
// "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p".
func Akamai(s HTTP2Settings, pseudo []string) string {
	var settings, prio, ps []string
	for _, st := range s.Settings {
		settings = append(settings, fmt.Sprintf("%d:%d", st.ID, st.Value))
	}
	wu := "00"
	if s.ConnectionWindowUpdate != 0 {
		wu = strconv.FormatUint(uint64(s.ConnectionWindowUpdate), 10)
	}
	for _, f := range s.PriorityFrames {
		excl := 0
		if f.Exclusive {
			excl = 1
		}
		prio = append(prio, fmt.Sprintf("%d:%d:%d:%d", f.StreamID, excl, f.StreamDep, int(f.Weight)+1))
	}
	if len(prio) == 0 {
		prio = []string{"0"}
	}
	for _, p := range pseudo {
		if len(p) > 1 {
			ps = append(ps, p[1:2])
		}
	}
	return strings.Join(settings, ";") + "|" + wu + "|" + strings.Join(prio, ",") + "|" + strings.Join(ps, ",")
}

// ParseAkamai reads an Akamai fingerprint, as the function Akamai writes
// it, into the
// SETTINGS, the connection WINDOW_UPDATE and the PRIORITY frames of base,
// and returns them with the pseudo-header order, for Profile.PseudoOrder.
// The other fields of base, such as Priority or HPACK, are kept: the
// fingerprint does not say them.
//
// Besides what Akamai writes, SETTINGS may be joined with ",", and
// WINDOW_UPDATE may be "0" or empty for none. An empty SETTINGS part, or
// "0", is no setting. The pseudo-header letters are m, a, s and p, each at
// most once. The result is validated as WithHTTP2Settings validates, so a
// fingerprint without ENABLE_PUSH 0 is refused; every error wraps
// ErrConfig.
func ParseAkamai(fp string, base HTTP2Settings) (HTTP2Settings, []string, error) {
	s, pseudo, err := parseAkamai(fp, base)
	if err == nil {
		_, err = h2Preface(s)
	}
	if err != nil {
		return HTTP2Settings{}, nil, fmt.Errorf("ParseAkamai: %w: %w", ErrConfig, err)
	}
	return s, pseudo, nil
}

func parseAkamai(fp string, s HTTP2Settings) (HTTP2Settings, []string, error) {
	parts := strings.Split(fp, "|")
	if len(parts) != 4 {
		return s, nil, fmt.Errorf("%d parts, want 4", len(parts))
	}
	s.Settings = nil
	if p := parts[0]; p != "" && p != "0" {
		sep := ";"
		if !strings.Contains(p, ";") {
			sep = ","
		}
		for _, kv := range strings.Split(p, sep) {
			k, v, _ := strings.Cut(kv, ":") // without ":", v is empty
			id, err1 := strconv.ParseUint(k, 10, 16)
			val, err2 := strconv.ParseUint(v, 10, 32)
			if err1 != nil || err2 != nil {
				return s, nil, fmt.Errorf("setting %q", kv)
			}
			s.Settings = append(s.Settings, HTTP2Setting{ID: uint16(id), Value: uint32(val)})
		}
	}
	s.ConnectionWindowUpdate = 0
	if p := parts[1]; p != "" { // "0" and "00" are none too
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return s, nil, fmt.Errorf("window update %q", p)
		}
		s.ConnectionWindowUpdate = uint32(v)
	}
	s.PriorityFrames = nil
	if p := parts[2]; p != "0" {
		for _, e := range strings.Split(p, ",") {
			f := strings.Split(e, ":")
			if len(f) != 4 {
				return s, nil, fmt.Errorf("priority %q", e)
			}
			id, err1 := strconv.ParseUint(f[0], 10, 31)
			dep, err2 := strconv.ParseUint(f[2], 10, 31)
			w, err3 := strconv.ParseUint(f[3], 10, 16)
			if err1 != nil || err2 != nil || err3 != nil || f[1] != "0" && f[1] != "1" || w < 1 || w > 256 {
				return s, nil, fmt.Errorf("priority %q", e)
			}
			s.PriorityFrames = append(s.PriorityFrames, HTTP2PriorityFrame{
				StreamID:           uint32(id),
				HTTP2PriorityParam: HTTP2PriorityParam{StreamDep: uint32(dep), Exclusive: f[1] == "1", Weight: uint8(w - 1)},
			})
		}
	}
	var pseudo []string
	for _, l := range strings.Split(parts[3], ",") {
		name, ok := akamaiPseudo[l]
		if !ok || slices.Contains(pseudo, name) {
			return s, nil, fmt.Errorf("pseudo-header %q", l)
		}
		pseudo = append(pseudo, name)
	}
	return s, pseudo, nil
}
