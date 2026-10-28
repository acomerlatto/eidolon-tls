// A server that reports the frames the client sends (patches 0022 on).

package http2

import (
	"bytes"
	"io"
	"net"
	"slices"

	"github.com/acomerlatto/eidolon-tls/internal/http2/hpack"
)

// wireFrame is a frame the client sent.
type wireFrame struct {
	typ    FrameType
	stream uint32
	flags  Flags
	length uint32
	block  []byte        // HEADERS fragment
	ping   [8]byte       // PING payload
	incr   uint32        // WINDOW_UPDATE increment
	code   ErrCode       // RST_STREAM and GOAWAY error code
	prio   PriorityParam // PRIORITY, and HEADERS with the flag
}

// wireOptions is how wireServer answers.
type wireOptions struct {
	settings []Setting
	noPings  bool   // leave the client's PINGs unanswered
	silent   bool   // and the requests too
	body     []byte // of each response, in DATA frames of 16384 bytes
}

// wireServer announces o.settings and a connection window of 1 GiB, then
// reports each frame the client sends on c. It acknowledges SETTINGS and
// PING, and answers each request with 200 and o.body once its stream ends.
func wireServer(c net.Conn, o wireOptions) <-chan wireFrame {
	seen := make(chan wireFrame, 1024)
	go func() {
		defer close(seen)
		defer c.Close()
		if _, err := io.ReadFull(c, make([]byte, len(ClientPreface))); err != nil {
			return
		}
		fr := NewFramer(c, c)
		writes := make(chan func(), 64)
		defer close(writes)
		go func() {
			for w := range writes {
				w()
			}
		}()
		writes <- func() { fr.WriteSettings(o.settings...); fr.WriteWindowUpdate(0, 1<<30) }
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			h := f.Header()
			w := wireFrame{typ: h.Type, stream: h.StreamID, flags: h.Flags, length: h.Length}
			end := false
			switch f := f.(type) {
			case *SettingsFrame:
				if !f.IsAck() {
					writes <- func() { fr.WriteSettingsAck() }
				}
			case *PingFrame:
				w.ping = f.Data
				if !f.IsAck() && !o.noPings && !o.silent {
					writes <- func() { fr.WritePing(true, f.Data) }
				}
			case *WindowUpdateFrame:
				w.incr = f.Increment
			case *RSTStreamFrame:
				w.code = f.ErrCode
			case *GoAwayFrame:
				w.code = f.ErrCode
			case *PriorityFrame:
				w.prio = f.PriorityParam
			case *HeadersFrame:
				w.prio = f.Priority
				w.block = slices.Clone(f.HeaderBlockFragment())
				end = f.StreamEnded()
			case *DataFrame:
				end = f.StreamEnded()
			}
			seen <- w
			if end && !o.silent {
				respond(writes, fr, h.StreamID, o.body)
			}
		}
	}()
	return seen
}

// respond queues on writes a response with 200 and body on stream id.
func respond(writes chan<- func(), fr *Framer, id uint32, body []byte) {
	var block bytes.Buffer
	hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	writes <- func() {
		fr.WriteHeaders(HeadersFrameParam{StreamID: id, EndHeaders: true, EndStream: len(body) == 0, BlockFragment: block.Bytes()})
		for b := body; len(b) > 0; {
			n := min(len(b), 16384)
			fr.WriteData(id, n == len(b), b[:n])
			b = b[n:]
		}
	}
}
