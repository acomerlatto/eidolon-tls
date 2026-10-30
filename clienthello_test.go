package eidolon_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	utls "github.com/acomerlatto/utls"
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

// extEncryptedClientHello is the type of encrypted_client_hello.
const extEncryptedClientHello = 0xfe0d

// withGREASEECH returns record with its encrypted_client_hello rebuilt
// with kdf, aead, an enc of encLen bytes and a payload of payloadLen.
func withGREASEECH(t *testing.T, record []byte, kdf, aead uint16, encLen, payloadLen int) []byte {
	t.Helper()
	s := cryptobyte.String(record[9:]) // after the record and handshake headers
	var head []byte
	var sid, cs, comp, exts cryptobyte.String
	if !s.ReadBytes(&head, 2+32) || !s.ReadUint8LengthPrefixed(&sid) || !s.ReadUint16LengthPrefixed(&cs) ||
		!s.ReadUint8LengthPrefixed(&comp) || !s.ReadUint16LengthPrefixed(&exts) || !s.Empty() {
		t.Fatal("malformed ClientHello")
	}
	var b cryptobyte.Builder
	b.AddUint8(22)
	b.AddUint16(0x0301)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(head)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sid) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(cs) })
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(comp) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for !exts.Empty() {
					var typ uint16
					var body cryptobyte.String
					exts.ReadUint16(&typ)
					exts.ReadUint16LengthPrefixed(&body)
					b.AddUint16(typ)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						if typ != extEncryptedClientHello {
							b.AddBytes(body)
							return
						}
						b.AddUint8(0) // outer
						b.AddUint16(kdf)
						b.AddUint16(aead)
						b.AddUint8(7) // config_id
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, encLen)) })
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, payloadLen)) })
					})
				}
			})
		})
	})
	return b.BytesOrPanic()
}

// greaseECHLens returns the payload lengths of the GREASE
// encrypted_client_hello in n ClientHellos of spec.
func greaseECHLens(t *testing.T, spec func() (*utls.ClientHelloSpec, error), n int) map[int]bool {
	t.Helper()
	lens := make(map[int]bool)
	for range n {
		s, err := spec()
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(s.Extensions, func(e utls.TLSExtension) bool {
			_, ok := e.(*utls.GREASEEncryptedClientHelloExtension)
			return ok
		})
		if i < 0 {
			t.Fatal("no GREASE encrypted_client_hello")
		}
		buf := make([]byte, s.Extensions[i].Len())
		s.Extensions[i].Read(buf)
		body := cryptobyte.String(buf[4:])
		var enc, payload cryptobyte.String
		if !body.Skip(1+4+1) || !body.ReadUint16LengthPrefixed(&enc) || !body.ReadUint16LengthPrefixed(&payload) {
			t.Fatal("malformed encrypted_client_hello")
		}
		lens[len(payload)] = true
	}
	return lens
}

// The GREASE encrypted_client_hello of a captured ClientHello draws its
// payload length on each connection when it has the shape BoringSSL gives
// it, as Chrome (setup_ech_grease); another keeps the captured length.
func TestClientHelloFromRawGREASEECH(t *testing.T) {
	const (
		sha256, sha384 = 1, 2
		aes128, aes256 = 1, 2
		chacha         = 3
		boringLens     = "144 176 208 240"
	)
	for _, tt := range []struct {
		name               string
		kdf, aead          uint16
		encLen, payloadLen int
		want               string
	}{
		{"BoringSSL", sha256, aes128, 32, 176, boringLens},
		{"BoringSSL ChaCha20", sha256, chacha, 32, 240, boringLens},
		{"other length", sha256, aes128, 32, 186, "186"},
		{"other KDF", sha384, aes128, 32, 176, "176"},
		{"other AEAD", sha256, aes256, 32, 176, "176"},
		{"other enc", sha256, aes128, 65, 176, "176"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := eidolon.ClientHelloFromRaw(withGREASEECH(t, chromeCapture(t), tt.kdf, tt.aead, tt.encLen, tt.payloadLen))
			if err != nil {
				t.Fatal(err)
			}
			// 4 lengths drawn 100 times: one is missing with a
			// probability under 2e-12.
			lens := slices.Sorted(maps.Keys(greaseECHLens(t, spec, 100)))
			if got := strings.Trim(fmt.Sprint(lens), "[]"); got != tt.want {
				t.Errorf("payload lengths %s, want %s", got, tt.want)
			}
		})
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
