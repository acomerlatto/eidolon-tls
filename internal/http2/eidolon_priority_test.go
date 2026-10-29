// Priority of HEADERS as Chromium's Http2PriorityDependencies (patch 0020).

package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/http2/hpack"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// The chain of the Chrome 156 capture (A10 section 3) and its edges.
func TestPriorityChain(t *testing.T) {
	type step struct {
		add    uint32 // stream to add, with urgency u
		u      uint8
		forget uint32 // or stream to forget
		dep    uint32 // dependency expected for add
		weight uint8
	}
	for _, tt := range []struct {
		name  string
		steps []step
	}{
		{"capture", []step{
			{add: 1, u: 0, dep: 0, weight: 255}, // CSS
			{add: 3, u: 2, dep: 1, weight: 182}, // image after CSS
			{add: 5, u: 3, dep: 3, weight: 146}, // script after image
			{forget: 1},
			{add: 7, u: 1, dep: 0, weight: 219}, // fetch: nothing as urgent open
			{add: 9, u: 1, dep: 7, weight: 219}, // POST after the open fetch
		}},
		{"same urgency first", []step{
			{add: 1, u: 2, dep: 0, weight: 182},
			{add: 3, u: 0, dep: 0, weight: 255},
			{add: 5, u: 2, dep: 1, weight: 182}, // the last u=2, not the more urgent 3
			{add: 7, u: 1, dep: 3, weight: 219},
		}},
		{"last of a level", []step{
			{add: 1, u: 4, dep: 0, weight: 109},
			{add: 3, u: 4, dep: 1, weight: 109},
			{add: 5, u: 4, dep: 3, weight: 109},
			{forget: 5},
			{add: 7, u: 7, dep: 3, weight: 0},
			{forget: 3},
			{add: 9, u: 5, dep: 1, weight: 73},
			{add: 11, u: 6, dep: 9, weight: 36},
		}},
		{"less urgent ignored", []step{
			{add: 1, u: 5, dep: 0, weight: 73},
			{add: 3, u: 2, dep: 0, weight: 182},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cc := &ClientConn{}
			for _, s := range tt.steps {
				if s.forget != 0 {
					cc.chainForgetLocked(s.forget)
					continue
				}
				cs := &clientStream{ID: s.add, urgency: s.u}
				cc.chainAddLocked(cs)
				want := PriorityParam{StreamDep: s.dep, Exclusive: true, Weight: s.weight}
				if cs.priority != want {
					t.Fatalf("stream %d: %+v, want %+v", s.add, cs.priority, want)
				}
			}
		})
	}
}

// The urgency comes from the priority field sent: the request's, or the
// exact field in exact mode; 3 without one or for an invalid u.
func TestChainUrgency(t *testing.T) {
	for _, tt := range []struct {
		header http.Header
		exact  []order.Field
		want   uint8
	}{
		{nil, nil, 3},
		{http.Header{"Priority": {"u=0, i"}}, nil, 0},
		{http.Header{"Priority": {"i", "u=5"}}, nil, 5},
		{http.Header{"priority": {"u=2"}}, nil, 2},
		{http.Header{"Priority": {"u=9"}}, nil, 3},
		{http.Header{"Priority": {"u=1;x"}}, nil, 1},
		{http.Header{"Priority": {"u=0"}}, []order.Field{{Name: "Host", Value: "example.com"}}, 3},
		{http.Header{"Priority": {"u=0"}}, []order.Field{{Name: "PRIORITY", Value: "u=6"}}, 6},
	} {
		ctx := context.Background()
		if tt.exact != nil {
			ctx = order.WithExact(ctx, tt.exact)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
		for k, v := range tt.header {
			req.Header[k] = v
		}
		if got := chainUrgency(req); got != tt.want {
			t.Errorf("header %v, exact %v: urgency %d, want %d", tt.header, tt.exact, got, tt.want)
		}
	}
}

// seenHeaders is a HEADERS frame the server received.
type seenHeaders struct {
	stream   uint32
	priority PriorityParam
	flagged  bool
}

// heldServer answers each request on c with 200 once its stream is sent on
// release, and reports the HEADERS frames it receives.
func heldServer(c net.Conn) (<-chan seenHeaders, chan<- uint32) {
	seen := make(chan seenHeaders, 16)
	release := make(chan uint32, 16)
	go func() {
		defer c.Close()
		if _, err := io.ReadFull(c, make([]byte, len(ClientPreface))); err != nil {
			return
		}
		fr := NewFramer(c, c)
		writes := make(chan func(), 16)
		defer close(writes)
		go func() {
			for w := range writes {
				w()
			}
		}()
		go func() {
			for id := range release {
				var block bytes.Buffer
				hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				writes <- func() {
					fr.WriteHeaders(HeadersFrameParam{StreamID: id, EndHeaders: true, EndStream: true, BlockFragment: block.Bytes()})
				}
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
				seen <- seenHeaders{f.StreamID, f.Priority, f.HasPriority()}
			}
		}
	}()
	return seen, release
}

// On the wire: the HEADERS carry the PRIORITY flag with the chain of the
// open streams, and a stream answered leaves the chain; without
// PriorityChain there is no flag.
func TestPriorityChainSent(t *testing.T) {
	for _, chain := range []bool{true, false} {
		t.Run(fmt.Sprint(chain), func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { client.Close() })
			seen, release := heldServer(server)
			defer close(release)
			cc, err := (&Transport{PriorityChain: chain}).newClientConn(client, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			send := func(priority string) (seenHeaders, <-chan error) {
				t.Helper()
				req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
				if priority != "" {
					req.Header.Set("Priority", priority)
				}
				done := make(chan error, 1)
				go func() {
					resp, err := cc.RoundTrip(req)
					if err == nil {
						resp.Body.Close()
					}
					done <- err
				}()
				select {
				case h := <-seen:
					return h, done
				case <-time.After(5 * time.Second):
					t.Fatal("no HEADERS")
				}
				return seenHeaders{}, nil
			}
			// wait waits for the request of stream id and for the client
			// to forget the stream, which happens after RoundTrip returns.
			wait := func(id uint32, done <-chan error) {
				t.Helper()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
					cc.mu.Lock()
					_, open := cc.streams[id]
					cc.mu.Unlock()
					if !open {
						return
					}
					if time.Now().After(deadline) {
						t.Fatalf("stream %d not forgotten", id)
					}
				}
			}
			css, cssDone := send("u=0")
			img, imgDone := send("u=2, i")
			script, scriptDone := send("")
			release <- css.stream
			wait(css.stream, cssDone)
			fetch, fetchDone := send("u=1, i")
			post, postDone := send("u=1, i")
			for _, id := range []uint32{img.stream, script.stream, fetch.stream, post.stream} {
				release <- id
			}
			wait(img.stream, imgDone)
			wait(script.stream, scriptDone)
			wait(fetch.stream, fetchDone)
			wait(post.stream, postDone)
			got := []seenHeaders{css, img, script, fetch, post}
			want := []seenHeaders{
				{1, PriorityParam{StreamDep: 0, Exclusive: true, Weight: 255}, true},
				{3, PriorityParam{StreamDep: 1, Exclusive: true, Weight: 182}, true},
				{5, PriorityParam{StreamDep: 3, Exclusive: true, Weight: 146}, true},
				{7, PriorityParam{StreamDep: 0, Exclusive: true, Weight: 219}, true},
				{9, PriorityParam{StreamDep: 7, Exclusive: true, Weight: 219}, true},
			}
			for i := range want {
				if !chain {
					want[i].priority, want[i].flagged = PriorityParam{}, false
				}
				if got[i] != want[i] {
					t.Errorf("request %d: %+v, want %+v", i, got[i], want[i])
				}
			}
		})
	}
}

// blockedClose is a request body whose Close reports on entered, then
// waits for release.
type blockedClose struct {
	io.Reader
	entered, release chan struct{}
}

func (b blockedClose) Close() error {
	close(b.entered)
	<-b.release
	return nil
}

// A request whose HEADERS are never written, here refused for an invalid
// header field, leaves the chain before the next request takes its place:
// the next one depends on the last stream sent, even while the refused
// request is still cleaning up, its body closing.
func TestPriorityChainUnsent(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	seen, release := heldServer(server)
	defer close(release)
	cc, err := (&Transport{PriorityChain: true}).newClientConn(client, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip := func(value string, body io.ReadCloser) error {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.Header.Set("Priority", "u=0")
		req.Header["X-Value"] = []string{value}
		if body != nil {
			req.Method, req.Body, req.ContentLength = http.MethodPost, body, 1
		}
		resp, err := cc.RoundTrip(req)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	first := make(chan error, 1)
	go func() { first <- roundTrip("ok", nil) }()
	h := <-seen
	closing := blockedClose{strings.NewReader("x"), make(chan struct{}), make(chan struct{})}
	refused := make(chan error, 1)
	go func() { refused <- roundTrip("a\nb", closing) }()
	<-closing.entered
	third := make(chan error, 1)
	go func() { third <- roundTrip("ok", nil) }()
	h3 := <-seen
	if h3.priority.StreamDep != h.stream {
		t.Errorf("stream %d depends on %d, want %d", h3.stream, h3.priority.StreamDep, h.stream)
	}
	close(closing.release)
	if err := <-refused; err == nil {
		t.Fatal("invalid header field sent")
	}
	release <- h.stream
	release <- h3.stream
	for _, done := range []chan error{first, third} {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
