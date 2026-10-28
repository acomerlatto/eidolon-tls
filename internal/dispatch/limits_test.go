package dispatch_test

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// writeBigHeaders answers stream with a header list of about size bytes in
// n fields, split in HEADERS and CONTINUATION frames, whatever the client
// announced.
func writeBigHeaders(fr *http2.Framer, stream uint32, size, n int) {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	for i := range n {
		enc.WriteField(hpack.HeaderField{Name: fmt.Sprintf("x-big-%d", i), Value: strings.Repeat("a", size/n)})
	}
	b := block.Bytes()
	const chunk = 16 << 10
	first := min(chunk, len(b))
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: b[:first], EndHeaders: first == len(b)})
	for b = b[first:]; len(b) > 0; {
		n := min(chunk, len(b))
		fr.WriteContinuation(stream, n == len(b), b[:n])
		b = b[n:]
	}
	fr.WriteData(stream, true, []byte("h2"))
}

// Response headers are bounded to 256 KiB by default, as Chrome, on both
// engines, with one error; over HTTP/2 the client announces the same limit.
// One field over the limit stops the HPACK decoder and the connection;
// many smaller ones only fail the stream.
func TestResponseHeaderLimit(t *testing.T) {
	for _, tt := range []struct {
		name string
		size int
		ok   bool
	}{
		{"under", 200 << 10, true},
		{"over", 300 << 10, false},
	} {
		t.Run("http/1.1/"+tt.name, func(t *testing.T) {
			big := strings.Repeat("a", tt.size)
			srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hijack(w, "HTTP/1.1 200 OK\r\nX-Big: "+big+"\r\nContent-Length: 2\r\n\r\nok", true)
			})})
			tr := transport(srv)
			defer tr.Close()
			_, _, err := do(t, tr, http.MethodGet, "https://example.com/", "")
			if tt.ok && err != nil {
				t.Fatal(err)
			}
			if !tt.ok && !errors.Is(err, http1.ErrHeaderTooLarge) {
				t.Fatalf("err = %v, want ErrHeaderTooLarge", err)
			}
		})
		for _, fields := range []int{1, 30} {
			t.Run(fmt.Sprintf("h2/%s/%d fields", tt.name, fields), func(t *testing.T) {
				srv := lab.Start(t, lab.Options{H2Conn: rawH2(func(fr *http2.Framer, stream uint32, _ int) bool {
					writeBigHeaders(fr, stream, tt.size, fields)
					return true
				})})
				tr := transport(srv)
				defer tr.Close()
				_, _, err := do(t, tr, http.MethodGet, "https://example.com/", "")
				if tt.ok && err != nil {
					t.Fatal(err)
				}
				if !tt.ok && !errors.Is(err, http1.ErrHeaderTooLarge) {
					t.Fatalf("err = %v, want ErrHeaderTooLarge", err)
				}
				frames, ferr := srv.NextConn(t).H2Frames()
				if ferr != nil {
					t.Fatal(ferr)
				}
				if got := settingValue(frames, uint16(http2.SettingMaxHeaderListSize)); got != 256<<10 {
					t.Fatalf("SETTINGS_MAX_HEADER_LIST_SIZE = %d, want %d", got, 256<<10)
				}
			})
		}
	}
}

func settingValue(frames []lab.H2Frame, id uint16) uint32 {
	for _, f := range frames {
		for _, s := range f.Settings {
			if s.ID == id {
				return s.Val
			}
		}
	}
	return 0
}

// The transport limit reaches both engines.
func TestResponseHeaderLimitSet(t *testing.T) {
	big := strings.Repeat("a", 4<<10)
	srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijack(w, fmt.Sprintf("HTTP/1.1 200 OK\r\nX-Big: %s\r\nContent-Length: 2\r\n\r\nok", big), true)
	})})
	tr := transport(srv)
	tr.MaxResponseHeaderBytes = 2 << 10
	defer tr.Close()
	if _, _, err := do(t, tr, http.MethodGet, "https://example.com/", ""); !errors.Is(err, http1.ErrHeaderTooLarge) {
		t.Fatalf("err = %v, want ErrHeaderTooLarge", err)
	}

	h2srv := lab.Start(t, lab.Options{H2Conn: rawH2(func(fr *http2.Framer, stream uint32, _ int) bool {
		writeOK(fr, stream)
		return true
	})})
	h2tr := transport(h2srv)
	h2tr.MaxResponseHeaderBytes = 64 << 10
	defer h2tr.Close()
	if _, _, err := do(t, h2tr, http.MethodGet, "https://example.com/", ""); err != nil {
		t.Fatal(err)
	}
	frames, err := h2srv.NextConn(t).H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	if got := settingValue(frames, uint16(http2.SettingMaxHeaderListSize)); got != 64<<10 {
		t.Fatalf("SETTINGS_MAX_HEADER_LIST_SIZE = %d", got)
	}
	// The limit goes into a copy of DefaultH2.
	if got := dispatch.DefaultH2.Settings[3]; got.ID != http2.SettingMaxHeaderListSize || got.Val != 262144 {
		t.Fatalf("DefaultH2 changed: %v", got)
	}
	// Chromium's preface PING, which a test on the wire cannot wait for.
	if dispatch.DefaultH2.PrefacePing != 10*time.Second {
		t.Fatalf("DefaultH2.PrefacePing %v", dispatch.DefaultH2.PrefacePing)
	}

	// Above what the 32-bit setting announces, the limit is the largest
	// value it announces (2^32-1 means no limit); it used to be cut to the
	// low 32 bits (5 here).
	h2tr = transport(h2srv)
	h2tr.MaxResponseHeaderBytes = 1<<32 + 5
	defer h2tr.Close()
	if _, _, err := do(t, h2tr, http.MethodGet, "https://example.com/", ""); err != nil {
		t.Fatal(err)
	}
	if frames, err = h2srv.NextConn(t).H2Frames(); err != nil {
		t.Fatal(err)
	}
	if got := settingValue(frames, uint16(http2.SettingMaxHeaderListSize)); got != math.MaxUint32-1 {
		t.Fatalf("SETTINGS_MAX_HEADER_LIST_SIZE = %d, want %d", got, uint32(math.MaxUint32-1))
	}
}

// A header list over the limit within one HEADERS frame fails only its
// stream, with the same error, and the connection goes on.
func TestResponseHeaderLimitStream(t *testing.T) {
	srv := lab.Start(t, lab.Options{H2Conn: rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
		if n == 1 {
			writeBigHeaders(fr, stream, 4<<10, 8) // one frame, no CONTINUATION
		} else {
			writeOK(fr, stream)
		}
		return true
	})})
	tr := transport(srv)
	tr.MaxResponseHeaderBytes = 2 << 10
	defer tr.Close()
	_, _, err := do(t, tr, http.MethodGet, "https://example.com/", "")
	var se http2.StreamError
	if !errors.Is(err, http1.ErrHeaderTooLarge) || !errors.As(err, &se) {
		t.Fatalf("err = %v, want ErrHeaderTooLarge from a stream error", err)
	}
	if _, body, err := do(t, tr, http.MethodGet, "https://example.com/", ""); err != nil || body != "h2" {
		t.Fatalf("next request: %q, %v", body, err)
	}
	if n := srv.Accepted(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
}
