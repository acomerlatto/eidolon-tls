package eidolon_test

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	eidolon "github.com/acomerlatto/eidolon-tls"
)

// The fingerprint of the Chrome profile is the one of Chrome 156.
func TestAkamaiChrome(t *testing.T) {
	p := eidolon.Chrome156Linux()
	if got, want := eidolon.Akamai(p.HTTP2, p.PseudoOrder), "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"; got != want {
		t.Errorf("%s, want %s", got, want)
	}
}

// Without WINDOW_UPDATE it writes "00"; an exclusive PRIORITY is 1; a
// pseudo-header field gives its second letter, and a name too short to
// have one is left out.
func TestAkamaiWrite(t *testing.T) {
	s := eidolon.HTTP2Settings{
		Settings:       []eidolon.HTTP2Setting{{ID: 1, Value: 1}},
		PriorityFrames: []eidolon.HTTP2PriorityFrame{{StreamID: 3, HTTP2PriorityParam: eidolon.HTTP2PriorityParam{Exclusive: true, Weight: 255}}},
	}
	if got, want := eidolon.Akamai(s, []string{"", ":", ":x", ":method"}), "1:1|00|3:1:0:256|x,m"; got != want {
		t.Errorf("%s, want %s", got, want)
	}
	read, _, err := eidolon.ParseAkamai("1:1|00|3:1:0:256|m", eidolon.HTTP2Settings{FirstStreamID: 5})
	if err != nil || !reflect.DeepEqual(read.PriorityFrames, s.PriorityFrames) {
		t.Errorf("%+v, %v", read.PriorityFrames, err)
	}
}

// A fingerprint read and written again is the same, with the fields it
// does not say kept from the base: here the tree of Firefox up to 88.
func TestParseAkamai(t *testing.T) {
	const firefox = "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s"
	base := eidolon.HTTP2Settings{
		Priority:       eidolon.HTTP2PriorityFixed,
		HeaderPriority: eidolon.HTTP2PriorityParam{StreamDep: 13, Weight: 41},
		FirstStreamID:  15,
		HPACK:          eidolon.HTTP2HPACKChromium,
		Settings:       []eidolon.HTTP2Setting{{ID: 3, Value: 100}},
	}
	s, pseudo, err := eidolon.ParseAkamai(firefox, base)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pseudo, []string{":method", ":path", ":authority", ":scheme"}) {
		t.Errorf("pseudo %q", pseudo)
	}
	if s.HPACK != base.HPACK || s.FirstStreamID != 15 || s.HeaderPriority != base.HeaderPriority || len(s.Settings) != 3 ||
		s.PriorityFrames[3] != (eidolon.HTTP2PriorityFrame{StreamID: 9, HTTP2PriorityParam: eidolon.HTTP2PriorityParam{StreamDep: 7}}) {
		t.Errorf("%+v", s)
	}
	if got := eidolon.Akamai(s, pseudo); got != firefox {
		t.Errorf("written again %s", got)
	}
}

// Besides what Akamai writes, SETTINGS joined with "," and a
// WINDOW_UPDATE of "0" or "" are read; SETTINGS "0" or "" are none, and
// so is PRIORITY "0", whatever the base had.
func TestParseAkamaiTolerated(t *testing.T) {
	want := eidolon.HTTP2Settings{Settings: []eidolon.HTTP2Setting{{ID: 1, Value: 65536}, {ID: 4, Value: 6291456}}}
	for _, fp := range []string{"1:65536,4:6291456|0|0|m,a,s,p", "1:65536;4:6291456||0|m,a,s,p", "1:65536;4:6291456|00|0|m,a,s,p"} {
		s, _, err := eidolon.ParseAkamai(fp, eidolon.HTTP2Settings{ConnectionWindowUpdate: 1})
		if err != nil || !reflect.DeepEqual(s, want) {
			t.Errorf("%s: %+v, %v", fp, s, err)
		}
	}
	for _, fp := range []string{"0|00|0|m", "|00|0|m"} {
		s, pseudo, err := eidolon.ParseAkamai(fp, eidolon.HTTP2Settings{
			Settings:       []eidolon.HTTP2Setting{{ID: 1, Value: 1}},
			PriorityFrames: []eidolon.HTTP2PriorityFrame{{StreamID: 3}},
			FirstStreamID:  5,
		})
		if err != nil || s.Settings != nil || s.PriorityFrames != nil || !slices.Equal(pseudo, []string{":method"}) {
			t.Errorf("%s: %+v, %q, %v", fp, s, pseudo, err)
		}
	}
}

// What is not a fingerprint, or not valid settings, is refused with
// ErrConfig.
func TestParseAkamaiInvalid(t *testing.T) {
	for _, fp := range []string{
		"1:65536|00|0",
		"1:65536|00|0|m,a,s,p|x",
		"1=65536|00|0|m,a,s,p",
		"1:x|00|0|m,a,s,p",
		"70000:1|00|0|m,a,s,p",
		"1:65536|x|0|m,a,s,p",
		"1:65536|00|3:0:0|m,a,s,p",
		"1:65536|00|3:2:0:1|m,a,s,p",
		"1:65536|00|3:0:0:0|m,a,s,p",
		"1:65536|00|3:0:0:257|m,a,s,p",
		"1:65536|00|x:0:0:1|m,a,s,p",
		"1:65536|00|0|m,a,s,x",
		"1:65536|00|0|m,a,m",
		"1:65536|00|0|",
		"2:1|00|0|m,a,s,p",             // ENABLE_PUSH 1
		"1:65536|2147483648|0|m,a,s,p", // a window over 2^31-1
		"1:65536|00|0:0:0:1|m,a,s,p",   // PRIORITY on stream 0
		"1:65536|00|3:0:3:1|m,a,s,p",   // a stream on itself
	} {
		if _, _, err := eidolon.ParseAkamai(fp, eidolon.HTTP2Settings{}); !errors.Is(err, eidolon.ErrConfig) {
			t.Errorf("%s: %v, want ErrConfig", fp, err)
		}
	}
}
