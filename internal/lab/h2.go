package lab

import (
	"bytes"
	"errors"
	"io"

	xhttp2 "golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var errNoPreface = errors.New("lab: missing HTTP/2 client preface")

// Setting is one HTTP/2 setting, in wire order.
type Setting struct {
	ID  uint16
	Val uint32
}

// HeaderField is one decoded header field, in wire order.
type HeaderField struct {
	Name, Value string
}

// Priority is the priority information of a PRIORITY frame or of a HEADERS
// frame with the PRIORITY flag.
type Priority struct {
	StreamDep uint32
	Exclusive bool
	Weight    uint8
}

// H2Frame is one frame sent by the client. HEADERS and its CONTINUATION
// frames are reported as one HEADERS frame with the decoded fields.
type H2Frame struct {
	Type     string // "SETTINGS", "WINDOW_UPDATE", "HEADERS", ...
	StreamID uint32
	Flags    uint8
	Length   uint32 // of the payload

	Settings  []Setting     // SETTINGS
	Increment uint32        // WINDOW_UPDATE
	Priority  *Priority     // PRIORITY, or HEADERS with the PRIORITY flag
	Headers   []HeaderField // HEADERS
	Block     []byte        // HEADERS without CONTINUATION: the HPACK block
	Ping      [8]byte       // PING
	ErrCode   uint32        // RST_STREAM and GOAWAY
}

// H2Frames decodes the client preface and the frames received so far. A
// frame still in transit at the end is left out.
func (c *Conn) H2Frames() ([]H2Frame, error) {
	data := c.Bytes()
	if !bytes.HasPrefix(data, []byte(xhttp2.ClientPreface)) {
		return nil, errNoPreface
	}
	// The decoded HEADERS no longer hold their block: take it first.
	blocks := headerBlocks(data[len(xhttp2.ClientPreface):])
	fr := xhttp2.NewFramer(io.Discard, bytes.NewReader(data[len(xhttp2.ClientPreface):]))
	// The lab server advertises the default table size, so the client's
	// encoder uses at most 4096 bytes.
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 1 << 20

	var frames []H2Frame
	for {
		f, err := fr.ReadFrame()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return frames, nil
		}
		if err != nil {
			return frames, err
		}
		h := f.Header()
		out := H2Frame{Type: h.Type.String(), StreamID: h.StreamID, Flags: uint8(h.Flags), Length: h.Length}
		switch f := f.(type) {
		case *xhttp2.SettingsFrame:
			f.ForeachSetting(func(s xhttp2.Setting) error {
				out.Settings = append(out.Settings, Setting{ID: uint16(s.ID), Val: s.Val})
				return nil
			})
		case *xhttp2.WindowUpdateFrame:
			out.Increment = f.Increment
		case *xhttp2.PingFrame:
			out.Ping = f.Data
		case *xhttp2.RSTStreamFrame:
			out.ErrCode = uint32(f.ErrCode)
		case *xhttp2.GoAwayFrame:
			out.ErrCode = uint32(f.ErrCode)
		case *xhttp2.PriorityFrame:
			out.Priority = &Priority{StreamDep: f.StreamDep, Exclusive: f.Exclusive, Weight: f.Weight}
		case *xhttp2.MetaHeadersFrame:
			out.Type = xhttp2.FrameHeaders.String()
			if f.HasPriority() {
				p := f.Priority
				out.Priority = &Priority{StreamDep: p.StreamDep, Exclusive: p.Exclusive, Weight: p.Weight}
			}
			for _, hf := range f.Fields {
				out.Headers = append(out.Headers, HeaderField{Name: hf.Name, Value: hf.Value})
			}
			out.Block, blocks = blocks[0], blocks[1:]
		}
		frames = append(frames, out)
	}
}

// headerBlocks returns the HPACK block of each HEADERS frame in data, in
// order: nil for one followed by CONTINUATION.
func headerBlocks(data []byte) [][]byte {
	fr := xhttp2.NewFramer(io.Discard, bytes.NewReader(data))
	var blocks [][]byte
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return blocks
		}
		if h, ok := f.(*xhttp2.HeadersFrame); ok {
			var b []byte
			if h.HeadersEnded() {
				b = bytes.Clone(h.HeaderBlockFragment())
			}
			blocks = append(blocks, b)
		}
	}
}
