// Bound of the wait for END_STREAM after a fully read response (patch 0009).

package http2

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/http2/hpack"
)

type lingerReset struct {
	at   time.Time
	code ErrCode
}

// lingerServer answers each request on c with a body of "ok", with
// END_STREAM only if end, and reports the RST_STREAM frames it receives.
func lingerServer(c net.Conn, end bool) <-chan lingerReset {
	resets := make(chan lingerReset, 1)
	go func() {
		defer c.Close()
		if _, err := io.ReadFull(c, make([]byte, len(ClientPreface))); err != nil {
			return
		}
		fr := NewFramer(c, c)
		// net.Pipe has no buffer: write from another goroutine, in order,
		// so the client's own writes never wait on ours.
		writes := make(chan func(), 8)
		defer close(writes)
		go func() {
			for w := range writes {
				w()
			}
		}()
		writes <- func() { fr.WriteSettings() }
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *SettingsFrame:
				if !f.IsAck() {
					writes <- func() { fr.WriteSettingsAck() }
				}
			case *HeadersFrame:
				var block bytes.Buffer
				enc := hpack.NewEncoder(&block)
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "2"})
				id := f.StreamID
				writes <- func() {
					fr.WriteHeaders(HeadersFrameParam{StreamID: id, EndHeaders: true, BlockFragment: block.Bytes()})
					fr.WriteData(id, end, []byte("ok"))
				}
			case *RSTStreamFrame:
				resets <- lingerReset{time.Now(), f.ErrCode}
			}
		}
	}()
	return resets
}

// lingerRequest sends req on a connection to lingerServer, reads the body
// in full and closes it, then cancels the request context. It returns when
// the body was closed, and the resets the server received.
func lingerRequest(t *testing.T, method string, body io.Reader) (time.Time, <-chan lingerReset) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	resets := lingerServer(server, false)
	cc, err := (&Transport{}).newClientConn(client, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, method, "https://example.com/", body)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(io.LimitReader(resp.Body, 2)); err != nil || string(got) != "ok" {
		t.Fatalf("body %q, %v", got, err)
	}
	closed := time.Now()
	resp.Body.Close()
	return closed, resets
}

// A response read in full whose END_STREAM never comes is reset with
// CANCEL once endStreamLinger passes, not before, even when the caller
// cancels its context right after closing the body.
func TestLingerForEndStreamBounded(t *testing.T) {
	defer func(d time.Duration) { endStreamLinger = d }(endStreamLinger)
	endStreamLinger = 300 * time.Millisecond

	closed, resets := lingerRequest(t, http.MethodGet, nil)
	select {
	case r := <-resets:
		if d := r.at.Sub(closed); d < endStreamLinger/2 {
			t.Fatalf("RST_STREAM %v after Close, before the linger of %v", d, endStreamLinger)
		}
		if r.code != ErrCodeCancel {
			t.Fatalf("RST_STREAM code %v, want CANCEL", r.code)
		}
	case <-time.After(10 * endStreamLinger):
		t.Fatal("no RST_STREAM: the stream lingers without bound")
	}
}

// A response read in full while the request body is still being sent does
// not linger: closing it resets the stream at once, which also stops the
// upload.
func TestNoLingerWhileSending(t *testing.T) {
	defer func(d time.Duration) { endStreamLinger = d }(endStreamLinger)
	endStreamLinger = 10 * time.Second

	pr, pw := io.Pipe()
	defer pw.Close()
	closed, resets := lingerRequest(t, http.MethodPost, pr)
	select {
	case r := <-resets:
		if r.code != ErrCodeCancel {
			t.Fatalf("RST_STREAM code %v, want CANCEL", r.code)
		}
		if d := r.at.Sub(closed); d > endStreamLinger/2 {
			t.Fatalf("RST_STREAM %v after Close", d)
		}
	case <-time.After(endStreamLinger / 2):
		t.Fatal("no RST_STREAM: the stream lingers with the upload unfinished")
	}
}

// A body read to EOF has its END_STREAM: closing it takes the usual path,
// which waits until the stream is forgotten, so the next request finds the
// connection idle (GotConnInfo.WasIdle, which the dispatcher's replay rule
// reads). The linger path returned at once.
func TestClosedAfterEOFForgotten(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	lingerServer(server, true)
	cc, err := (&Transport{}).newClientConn(client, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "ok" {
			cancel()
			t.Fatalf("body %q, %v", body, err)
		}
		resp.Body.Close()
		cancel()
		if n := cc.State().StreamsActive; n != 0 {
			t.Fatalf("request %d: %d active streams after Close", i, n)
		}
	}
}
