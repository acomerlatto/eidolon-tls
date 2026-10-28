package dispatch

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// maxDrain bounds what is read after the end of a compressed stream, so the
// body reaches EOF and an HTTP/1.1 connection can return to the pool.
const maxDrain = 4 << 10

// Decoders keep tens of kilobytes of window and tables; they are reused
// across responses instead of allocated for each one.
var (
	gzipPool   sync.Pool // *gzip.Reader
	zlibPool   sync.Pool // io.ReadCloser that is a zlib.Resetter
	flatePool  sync.Pool // io.ReadCloser that is a flate.Resetter
	brotliPool sync.Pool // *brotli.Reader
	zstdPool   sync.Pool // *zstd.Decoder
	bufioPool  = sync.Pool{New: func() any { return bufio.NewReader(nil) }}
)

// zstdMaxWindow is the largest zstd window decoded, as Chrome's
// ZstdSourceStream (window_log_max 23): a frame that needs more fails.
const zstdMaxWindow = 8 << 20

// decompress decodes a gzip, deflate, br or zstd body, as browsers do: the
// response loses Content-Encoding and Content-Length, and Uncompressed is
// set. Other codings, several codings, and responses without a body are
// left as they came. Decoding starts at the first Read, so a malformed body is reported
// by Read, never by RoundTrip.
func decompress(resp *http.Response) {
	if resp.Request != nil && resp.Request.Method == http.MethodHead ||
		resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified ||
		resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	values := resp.Header.Values("Content-Encoding")
	if len(values) != 1 {
		return
	}
	var coding string
	switch strings.ToLower(strings.TrimSpace(values[0])) {
	case "gzip", "x-gzip":
		coding = "gzip"
	case "deflate", "br", "zstd":
		coding = strings.ToLower(strings.TrimSpace(values[0]))
	default:
		return
	}
	resp.Body = &decodedBody{body: resp.Body, coding: coding}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Uncompressed = true
}

// decodedBody decodes body on Read and closes it on Close. Its decoder
// returns to the pools when the stream ends, fails or is closed; mu keeps
// Close from returning it while a Read uses it.
type decodedBody struct {
	body   io.ReadCloser
	coding string

	mu      sync.Mutex
	r       io.Reader // the decoder, from the first Read
	in      io.Reader // what the decoder reads: body or a pooled bufio.Reader
	release func()    // returns the decoder to its pools
	err     error     // sticky error, io.EOF included
}

func (d *decodedBody) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return 0, d.err
	}
	if d.r == nil {
		if err := d.start(); err != nil {
			d.done(err)
			return 0, err
		}
	}
	n, err := d.r.Read(p)
	if errors.Is(err, io.EOF) {
		// The stream ended; reach the EOF of the body so the connection
		// is released.
		if _, derr := io.CopyN(io.Discard, d.in, maxDrain); derr != nil && !errors.Is(derr, io.EOF) {
			err = derr
		}
	}
	if err != nil {
		d.done(err)
	}
	return n, err
}

// start takes a decoder from the pools, or makes one. The decoder reads
// through a pooled bufio.Reader: without an io.ByteReader the gzip and
// flate decoders would allocate one of their own. The zstd decoder works on
// the reading goroutine, as Chrome's, without goroutines of its own.
func (d *decodedBody) start() error {
	br := bufioPool.Get().(*bufio.Reader)
	br.Reset(d.body)
	d.in = br
	var pool *sync.Pool
	var dec io.Reader
	var err error
	switch {
	case d.coding == "gzip":
		pool = &gzipPool
		if zr, _ := pool.Get().(*gzip.Reader); zr != nil {
			dec, err = zr, zr.Reset(br)
		} else if zr, err = gzip.NewReader(br); zr != nil {
			dec = zr
		}
		if zr, _ := dec.(*gzip.Reader); zr != nil {
			// One member, as Chrome's GzipSourceStream: bytes after it are
			// ignored, not read as another member. Reset turns it back on.
			zr.Multistream(false)
		}
	case d.coding == "br":
		pool = &brotliPool
		if bdec, _ := pool.Get().(*brotli.Reader); bdec != nil {
			dec, err = bdec, bdec.Reset(br)
		} else {
			dec = brotli.NewReader(br)
		}
	case d.coding == "zstd":
		pool = &zstdPool
		if zdec, _ := pool.Get().(*zstd.Decoder); zdec != nil {
			dec, err = zdec, zdec.Reset(br)
		} else if zdec, err = zstd.NewReader(br, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(zstdMaxWindow)); zdec != nil {
			dec = zdec
		}
	case isZlib(br):
		// "deflate" is zlib (RFC 9110 section 8.4.1.2), but servers also
		// send raw deflate; browsers accept both.
		pool = &zlibPool
		if zr, _ := pool.Get().(io.ReadCloser); zr != nil {
			dec, err = zr, zr.(zlib.Resetter).Reset(br, nil)
		} else if zr, err = zlib.NewReader(br); zr != nil {
			dec = zr
		}
	default:
		pool = &flatePool
		if fr, _ := pool.Get().(io.ReadCloser); fr != nil {
			dec, err = fr, fr.(flate.Resetter).Reset(br, nil)
		} else {
			dec = flate.NewReader(br)
		}
	}
	d.r = dec
	d.release = func() {
		br.Reset(nil)
		bufioPool.Put(br)
		if dec != nil {
			pool.Put(dec)
		}
	}
	return err
}

// isZlib reports whether br starts with a zlib header (RFC 1950).
func isZlib(br *bufio.Reader) bool {
	h, err := br.Peek(2)
	return err == nil && h[0]&0x0f == 8 && (uint16(h[0])<<8|uint16(h[1]))%31 == 0
}

// done records the final error and returns the decoder to the pools.
func (d *decodedBody) done(err error) {
	d.err = err
	if d.release != nil {
		d.release()
		d.release = nil
	}
	d.r, d.in = nil, nil
}

func (d *decodedBody) Close() error {
	// Closing the body first unblocks a Read in progress, which then
	// lets go of mu.
	err := d.body.Close()
	d.mu.Lock()
	if d.err == nil {
		d.done(http.ErrBodyReadAfterClose)
	}
	d.mu.Unlock()
	return err
}
