package dispatch

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func compressed(coding, s string) []byte {
	var b bytes.Buffer
	var w io.WriteCloser
	switch coding {
	case "gzip":
		w = gzip.NewWriter(&b)
	case "zlib":
		w = zlib.NewWriter(&b)
	case "br":
		w = brotli.NewWriter(&b)
	case "zstd":
		w, _ = zstd.NewWriter(&b)
	default:
		w, _ = flate.NewWriter(&b, flate.DefaultCompression)
	}
	io.WriteString(w, s)
	w.Close()
	return b.Bytes()
}

func decodeOnce(t testing.TB, header string, payload []byte) string {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Encoding": {header}},
		Body:       io.NopCloser(bytes.NewReader(payload)),
	}
	decompress(resp)
	var out strings.Builder
	if _, err := io.Copy(&out, resp.Body); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return out.String()
}

var codings = []struct{ name, header string }{
	{"gzip", "gzip"}, {"zlib", "deflate"}, {"raw", "deflate"}, {"br", "br"}, {"zstd", "zstd"},
}

// BenchmarkDecompress reports the memory of decoding one body; the copy
// buffer and the source are reused, so what remains is the decoder's.
func BenchmarkDecompress(b *testing.B) {
	text := strings.Repeat("pooled decoder ", 200)
	buf := make([]byte, 32<<10)
	for _, c := range codings {
		payload := compressed(c.name, text)
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			src := bytes.NewReader(payload)
			resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
			for b.Loop() {
				src.Reset(payload)
				resp.Header["Content-Encoding"] = []string{c.header}
				resp.Body = io.NopCloser(src)
				decompress(resp)
				if _, err := io.CopyBuffer(struct{ io.Writer }{io.Discard}, resp.Body, buf); err != nil {
					b.Fatal(err)
				}
				resp.Body.Close()
			}
		})
	}
}

// Pooled decoders give the right output under concurrency, codings mixed.
func TestDecompressPooledConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			text := strings.Repeat("x", i*37) + "end"
			for _, c := range codings {
				for range 20 {
					if got := decodeOnce(t, c.header, compressed(c.name, text)); got != text {
						t.Errorf("%s: got %d bytes, want %d", c.name, len(got), len(text))
						return
					}
				}
			}
		})
	}
	wg.Wait()
}

// A malformed body fails on Read and the decoder it returned stays usable.
func TestDecompressPooledAfterError(t *testing.T) {
	for _, c := range codings {
		for range 3 {
			resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": {c.header}},
				Body: io.NopCloser(strings.NewReader("\x1f\x8b garbage that is not compressed"))}
			if c.name == "zlib" {
				resp.Body = io.NopCloser(strings.NewReader("\x78\x9c garbage"))
			}
			decompress(resp)
			if _, err := io.ReadAll(resp.Body); err == nil {
				t.Errorf("%s: malformed body read without error", c.name)
			}
			resp.Body.Close()
			if got := decodeOnce(t, c.header, compressed(c.name, "after")); got != "after" {
				t.Fatalf("%s: got %q after an error", c.name, got)
			}
		}
	}
}

// blockingBody returns data, then blocks until closed.
type blockingBody struct {
	data   []byte
	closed chan struct{}
	once   sync.Once
}

func (b *blockingBody) Read(p []byte) (int, error) {
	if len(b.data) > 0 {
		n := copy(p, b.data)
		b.data = b.data[n:]
		return n, nil
	}
	<-b.closed
	return 0, io.ErrUnexpectedEOF
}

func (b *blockingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// Close from another goroutine during a Read unblocks it, and the decoder
// goes back to the pool only once; later Reads fail.
func TestDecompressCloseDuringRead(t *testing.T) {
	for _, c := range codings {
		payload := compressed(c.name, strings.Repeat("partial ", 5000))
		body := &blockingBody{data: payload[:len(payload)/2], closed: make(chan struct{})}
		resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": {c.header}}, Body: body}
		decompress(resp)
		readErr := make(chan error, 1)
		go func() {
			_, err := io.Copy(io.Discard, resp.Body)
			readErr <- err
		}()
		resp.Body.Close()
		if err := <-readErr; err == nil {
			t.Errorf("%s: Read ended without error", c.name)
		}
		if _, err := resp.Body.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s: Read after Close succeeded", c.name)
		}
		resp.Body.Close()
		if got := decodeOnce(t, c.header, compressed(c.name, "next")); got != "next" {
			t.Fatalf("%s: got %q after Close", c.name, got)
		}
	}
}

// A body closed before the end of its stream returns its decoder too, and
// reads after Close fail with http.ErrBodyReadAfterClose.
func TestDecompressClosedEarly(t *testing.T) {
	text := strings.Repeat("closed early ", 2000)
	for _, c := range codings {
		payload := compressed(c.name, text)
		readHalf := func() *http.Response {
			resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": {c.header}},
				Body: io.NopCloser(bytes.NewReader(payload))}
			decompress(resp)
			if _, err := io.ReadFull(resp.Body, make([]byte, len(text)/2)); err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			return resp
		}
		if _, err := readHalf().Body.Read(make([]byte, 1)); !errors.Is(err, http.ErrBodyReadAfterClose) {
			t.Errorf("%s: Read after Close = %v", c.name, err)
		}
		if testing.Short() || raceEnabled {
			continue
		}
		const runs = 200
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for range runs {
			readHalf()
		}
		runtime.ReadMemStats(&after)
		// The half read itself allocates len(text)/2; a lost decoder
		// would add tens of kilobytes.
		if n := (after.TotalAlloc-before.TotalAlloc)/runs - uint64(len(text)/2); n > 8<<10 {
			t.Errorf("%s: %d bytes per closed body, want the decoder reused", c.name, n)
		}
	}
}

// The decoders are reused: decoding a body allocates far less than a new
// decoder's window.
func TestDecompressReusesDecoders(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("benchmark; the race detector drops pooled values")
	}
	text := strings.Repeat("pooled decoder ", 200)
	buf := make([]byte, 32<<10)
	for _, c := range codings {
		payload := compressed(c.name, text)
		src := bytes.NewReader(payload)
		resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
		decode := func() {
			src.Reset(payload)
			resp.Header["Content-Encoding"] = []string{c.header}
			resp.Body = io.NopCloser(src)
			decompress(resp)
			io.CopyBuffer(struct{ io.Writer }{io.Discard}, resp.Body, buf)
			resp.Body.Close()
		}
		decode() // fills the pools
		const runs = 500
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for range runs {
			decode()
		}
		runtime.ReadMemStats(&after)
		if n := (after.TotalAlloc - before.TotalAlloc) / runs; n > 4<<10 {
			t.Errorf("%s: %d bytes per body, want the decoder reused", c.name, n)
		}
	}
}

// A gzip body ends with its first member, as in Chrome: bytes after it,
// another member included, are ignored. Pooled decoders keep the rule.
func TestDecompressGzipOneMember(t *testing.T) {
	for _, extra := range [][]byte{[]byte("\x00\x00 trailing junk"), compressed("gzip", "second")} {
		for range 3 {
			payload := append(compressed("gzip", "first"), extra...)
			if got := decodeOnce(t, "gzip", payload); got != "first" {
				t.Fatalf("extra %q: got %q", extra, got)
			}
		}
	}
}

// zstd decodes windows up to 8 MiB, as Chrome; a frame that needs more
// fails on Read. The encoder shrinks the window to the content, so the
// content is above 8 MiB.
func TestDecompressZstdWindow(t *testing.T) {
	text := strings.Repeat("window ", 9<<20/7)
	for _, tt := range []struct {
		window int
		ok     bool
	}{{8 << 20, true}, {16 << 20, false}} {
		var b bytes.Buffer
		w, err := zstd.NewWriter(&b, zstd.WithWindowSize(tt.window), zstd.WithSingleSegment(false))
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(w, text)
		w.Close()
		resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": {"zstd"}}, Body: io.NopCloser(&b)}
		decompress(resp)
		got, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if tt.ok && (err != nil || string(got) != text) {
			t.Errorf("window %d: %.20q, %v", tt.window, got, err)
		}
		if !tt.ok && !errors.Is(err, zstd.ErrWindowSizeExceeded) {
			t.Errorf("window %d: error %v, want %v", tt.window, err, zstd.ErrWindowSizeExceeded)
		}
	}
}

// zstd decodes on the reading goroutine, as Chrome: no goroutine runs
// while a body is read, pooled decoders included.
func TestDecompressZstdNoGoroutines(t *testing.T) {
	payload := compressed("zstd", strings.Repeat("goroutines ", 4<<20/11))
	decodeOnce(t, "zstd", payload) // fills the pool
	before := runtime.NumGoroutine()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": {"zstd"}}, Body: io.NopCloser(bytes.NewReader(payload))}
	decompress(resp)
	defer resp.Body.Close()
	if _, err := resp.Body.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Fatalf("%d goroutines while reading, %d before", n, before)
	}
}
