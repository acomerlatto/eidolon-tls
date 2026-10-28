// DATA frames limited by MaxDataFrameSize (patch 0021).

package http2

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"slices"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/http2/hpack"
)

// dataServer announces settings and a connection window of 1 GiB, answers
// each request with 200 once its stream ends, and reports the payload
// lengths of the DATA frames of the stream once it ends.
func dataServer(c net.Conn, settings ...Setting) <-chan []int {
	seen := make(chan []int, 4)
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
		writes <- func() { fr.WriteSettings(settings...); fr.WriteWindowUpdate(0, 1<<30) }
		lengths := map[uint32][]int{}
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			end := false
			switch f := f.(type) {
			case *SettingsFrame:
				if !f.IsAck() {
					writes <- func() { fr.WriteSettingsAck() }
				}
			case *PingFrame:
				if !f.IsAck() {
					writes <- func() { fr.WritePing(true, f.Data) }
				}
			case *HeadersFrame:
				end = f.StreamEnded()
			case *DataFrame:
				lengths[f.StreamID] = append(lengths[f.StreamID], len(f.Data()))
				end = f.StreamEnded()
			}
			if end {
				id := f.Header().StreamID
				seen <- lengths[id]
				var block bytes.Buffer
				hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				writes <- func() {
					fr.WriteHeaders(HeadersFrameParam{StreamID: id, EndHeaders: true, EndStream: true, BlockFragment: block.Bytes()})
				}
			}
		}
	}()
	return seen
}

// The body goes in DATA frames of MaxDataFrameSize, below the peer's
// MAX_FRAME_SIZE, even from a larger pooled buffer; without it, as large
// as the peer and the scratch buffer allow.
func TestMaxDataFrameSize(t *testing.T) {
	const chunk = 16375
	for _, tt := range []struct {
		name   string
		limit  uint32
		peer   uint32 // MAX_FRAME_SIZE of the server, 0 for none
		body   int
		pooled bool // larger buffers in the pool
		want   []int
	}{
		// First: the buffers of chunk bytes the others leave in the pool
		// would be taken before the larger ones.
		{"pooled buffer", chunk, 1 << 20, 65536, true, []int{chunk, chunk, chunk, chunk, 36}},
		{"chrome", chunk, 1 << 20, 65536, false, []int{chunk, chunk, chunk, chunk, 36}},
		{"exact", chunk, 1 << 20, chunk, false, []int{chunk}},
		{"small", chunk, 1 << 20, 7, false, []int{7}},
		{"peer below", 20000, 0, 40000, false, []int{16384, 16384, 7232}},
		{"none", 0, 1 << 20, 65536, false, []int{65536}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { client.Close() })
			settings := []Setting{{ID: SettingInitialWindowSize, Val: 1 << 30}}
			if tt.peer != 0 {
				settings = append(settings, Setting{ID: SettingMaxFrameSize, Val: tt.peer})
			}
			seen := dataServer(server, settings...)
			tr := &Transport{MaxDataFrameSize: tt.limit}
			cc, err := tr.newClientConn(client, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := cc.Ping(t.Context()); err != nil { // the server SETTINGS are in force
				t.Fatal(err)
			}
			if tt.pooled {
				for range 8 {
					b := make([]byte, 16384)
					bufPools[0].Put(&b)
				}
			}
			req, _ := http.NewRequest(http.MethodPost, "https://example.com/", bytes.NewReader(make([]byte, tt.body)))
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if got := <-seen; !slices.Equal(got, tt.want) {
				t.Errorf("DATA frames %v, want %v", got, tt.want)
			}
		})
	}
}
