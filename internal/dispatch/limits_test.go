package dispatch_test

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// writeBigHeaders answers stream with a header list of about size bytes,
// split in HEADERS and CONTINUATION frames, whatever the client announced.
func writeBigHeaders(fr *http2.Framer, stream uint32, size int) {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	enc.WriteField(hpack.HeaderField{Name: "x-big", Value: strings.Repeat("a", size)})
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
// engines; over HTTP/2 the client announces the same limit.
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
		t.Run("h2/"+tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{H2Conn: rawH2(func(fr *http2.Framer, stream uint32, _ int) bool {
				writeBigHeaders(fr, stream, tt.size)
				return true
			})})
			tr := transport(srv)
			defer tr.Close()
			_, _, err := do(t, tr, http.MethodGet, "https://example.com/", "")
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok = %v", err, tt.ok)
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
}
