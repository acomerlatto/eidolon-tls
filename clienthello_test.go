package eidolon_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// helloShape returns the cipher suites and the extension types of a
// ClientHello handshake message, with GREASE values as "GREASE".
func helloShape(t *testing.T, msg []byte) (suites, exts []string) {
	t.Helper()
	name := func(v uint16) string {
		if v&0x0f0f == 0x0a0a && v>>8 == v&0xff {
			return "GREASE"
		}
		return fmt.Sprint(v)
	}
	s := cryptobyte.String(msg)
	var sid, cs, comp, ext cryptobyte.String
	if !s.Skip(4+2+32) || !s.ReadUint8LengthPrefixed(&sid) || !s.ReadUint16LengthPrefixed(&cs) ||
		!s.ReadUint8LengthPrefixed(&comp) || !s.ReadUint16LengthPrefixed(&ext) {
		t.Fatal("malformed ClientHello")
	}
	for !cs.Empty() {
		var v uint16
		cs.ReadUint16(&v)
		suites = append(suites, name(v))
	}
	for !ext.Empty() {
		var v uint16
		var body cryptobyte.String
		ext.ReadUint16(&v)
		ext.ReadUint16LengthPrefixed(&body)
		exts = append(exts, name(v))
	}
	return suites, exts
}

// chromeCapture returns the ClientHello record Chrome 156 sent (A10).
func chromeCapture(t *testing.T) []byte {
	raw, err := os.ReadFile("testdata/chrome156-linux-clienthello.bin")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// helloSent connects with spec and returns the ClientHello the lab got.
func helloSent(t *testing.T, opts ...eidolon.Option) []byte {
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	resp, err := newClient(t, srv, opts...).Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return srv.NextConn(t).ClientHello
}

// A captured ClientHello, as a record or a handshake message, is sent
// again with its cipher suites and its extensions in the captured order,
// whatever becomes of the bytes given.
func TestClientHelloFromRaw(t *testing.T) {
	record := chromeCapture(t)
	wantSuites, wantExts := helloShape(t, record[5:])
	for name, raw := range map[string][]byte{"record": record, "message": record[5:]} {
		t.Run(name, func(t *testing.T) {
			raw = bytes.Clone(raw)
			spec, err := eidolon.ClientHelloFromRaw(raw)
			if err != nil {
				t.Fatal(err)
			}
			clear(raw) // copied
			suites, exts := helloShape(t, helloSent(t, eidolon.WithClientHello(spec)))
			if !slices.Equal(suites, wantSuites) || !slices.Equal(exts, wantExts) {
				t.Errorf("suites %v, extensions %v; want %v, %v", suites, exts, wantSuites, wantExts)
			}
		})
	}
}

// A captured ClientHello that resumes a session leaves pre_shared_key
// out of the first connection and sends a real one, last, on the next
// ones, which resume in the captured shape; one captured without it, but
// with psk_key_exchange_modes, gets it at the end, as Chrome adds it.
func TestClientHelloFromRawResumption(t *testing.T) {
	resumedCapture, err := os.ReadFile("testdata/chrome156-linux-clienthello-resumed.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, resumedExts := helloShape(t, resumedCapture[5:])
	_, firstExts := helloShape(t, chromeCapture(t)[5:])
	for _, tt := range []struct {
		name        string
		raw         []byte
		first, next []string
	}{
		{"resumed", resumedCapture, slices.DeleteFunc(slices.Clone(resumedExts), func(e string) bool { return e == "41" }), resumedExts},
		{"first", chromeCapture(t), firstExts, append(slices.Clone(firstExts), "41")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := eidolon.ClientHelloFromRaw(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
			c := newClient(t, srv, eidolon.WithClientHello(spec))
			for i, want := range [][]string{tt.first, tt.next} {
				getNew(t, c, "https://example.com/")
				conn := srv.NextConn(t)
				if _, exts := helloShape(t, conn.ClientHello); !slices.Equal(exts, want) {
					t.Errorf("connection %d: extensions %v, want %v", i, exts, want)
				}
				if conn.State.DidResume != (i == 1) {
					t.Errorf("connection %d: resumed %v", i, conn.State.DidResume)
				}
			}
		})
	}
}

// WithShuffledExtensions shuffles the extensions on each connection, as
// Chrome, with GREASE in its places.
func TestClientHelloFromRawShuffled(t *testing.T) {
	_, want := helloShape(t, chromeCapture(t)[5:])
	spec, err := eidolon.ClientHelloFromRaw(chromeCapture(t), eidolon.WithShuffledExtensions())
	if err != nil {
		t.Fatal(err)
	}
	shuffled := false
	for range 8 {
		_, exts := helloShape(t, helloSent(t, eidolon.WithClientHello(spec)))
		if exts[0] != "GREASE" || exts[len(exts)-1] != "GREASE" ||
			!slices.Equal(slices.Sorted(slices.Values(exts)), slices.Sorted(slices.Values(want))) {
			t.Fatalf("extensions %v, want a shuffle of %v", exts, want)
		}
		shuffled = shuffled || !slices.Equal(exts, want)
	}
	if !shuffled {
		t.Error("8 ClientHellos in the captured order")
	}
}

// What is not a ClientHello, or announces what the stack cannot honor,
// is refused with ErrProfile.
func TestClientHelloFromRawInvalid(t *testing.T) {
	record := chromeCapture(t)
	// The SCT extension (18), second after GREASE, renamed early_data.
	earlyData := bytes.Clone(record)
	i := bytes.Index(earlyData, []byte{0, 18, 0, 0})
	earlyData[i+1] = 42
	for name, raw := range map[string][]byte{
		"empty":      nil,
		"junk":       []byte("GET / HTTP/1.1\r\n"),
		"truncated":  record[:100],
		"early_data": earlyData,
	} {
		if _, err := eidolon.ClientHelloFromRaw(raw); !errors.Is(err, eidolon.ErrProfile) {
			t.Errorf("%s: %v, want ErrProfile", name, err)
		}
	}
	if _, err := eidolon.ClientHelloFromRaw(record, nil); !errors.Is(err, eidolon.ErrConfig) {
		t.Errorf("nil option: %v, want ErrConfig", err)
	}
}
