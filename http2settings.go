package eidolon

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/http2"
)

// HTTP2Setting is one parameter of the SETTINGS frame that starts an
// HTTP/2 connection (RFC 9113 section 6.5.2).
type HTTP2Setting struct {
	ID    uint16
	Value uint32
}

// The SETTINGS parameters of RFC 9113 section 6.5.2, RFC 8441 and RFC 9218.
const (
	HTTP2SettingHeaderTableSize       uint16 = 0x1
	HTTP2SettingEnablePush            uint16 = 0x2
	HTTP2SettingMaxConcurrentStreams  uint16 = 0x3
	HTTP2SettingInitialWindowSize     uint16 = 0x4
	HTTP2SettingMaxFrameSize          uint16 = 0x5
	HTTP2SettingMaxHeaderListSize     uint16 = 0x6
	HTTP2SettingEnableConnectProtocol uint16 = 0x8
	HTTP2SettingNoRFC7540Priorities   uint16 = 0x9
)

// HTTP2Priority is how the requests of an HTTP/2 connection announce their
// priority in HEADERS.
type HTTP2Priority int

const (
	// HTTP2PriorityNone sends HEADERS without the PRIORITY flag.
	HTTP2PriorityNone HTTP2Priority = iota
	// HTTP2PriorityChromium sends HEADERS with the PRIORITY flag as
	// Chromium: the weight follows the urgency of the request's priority
	// field (RFC 9218; 255, 219, 182, 146, 109, 73, 36, 0 for u=0 to 7,
	// u=3 without one), and the stream depends exclusively on the last
	// open stream of that urgency, or else of the closest more urgent one,
	// or else on stream 0.
	HTTP2PriorityChromium
	// HTTP2PriorityFixed sends every HEADERS with the PRIORITY flag and
	// HTTP2Settings.HeaderPriority, as Firefox up to version 88 did.
	HTTP2PriorityFixed
)

// HTTP2PriorityParam is the priority of a stream, in a PRIORITY frame or in
// HEADERS (RFC 9113 section 6.3): the stream it depends on, whether the
// dependency is exclusive, and the weight as sent, one less than the
// weight (255 is 256).
type HTTP2PriorityParam struct {
	StreamDep uint32
	Exclusive bool
	Weight    uint8
}

// engine returns p for the HTTP/2 engine.
func (p HTTP2PriorityParam) engine() http2.PriorityParam {
	return http2.PriorityParam{StreamDep: p.StreamDep, Exclusive: p.Exclusive, Weight: p.Weight}
}

// HTTP2PriorityFrame is a PRIORITY frame sent before the first request.
type HTTP2PriorityFrame struct {
	StreamID uint32
	HTTP2PriorityParam
}

// HTTP2HPACK is how an HTTP/2 connection encodes header fields with HPACK
// (RFC 7541).
type HTTP2HPACK int

const (
	// HTTP2HPACKGo encodes as the HPACK encoder of Go: every field that
	// fits in the table is indexed, and the table never grows past 4096
	// bytes, with a size update whenever the server announces a size.
	HTTP2HPACKGo HTTP2HPACK = iota
	// HTTP2HPACKChromium encodes as Chromium (quiche's HpackEncoder): only
	// :authority among the pseudo-headers is indexed, and the table takes
	// any size the server announces, with a size update only when it
	// changes.
	HTTP2HPACKChromium
)

// HTTP2WindowUpdate is when an HTTP/2 connection gives back the receive
// windows of the connection and of its streams with WINDOW_UPDATE.
type HTTP2WindowUpdate int

const (
	// HTTP2WindowUpdateGo gives the window back as Go does, every 4 KiB
	// read.
	HTTP2WindowUpdateGo HTTP2WindowUpdate = iota
	// HTTP2WindowUpdateChromium gives it back as Chromium: once more than
	// half of the window has been read, or 5 s after the last update,
	// when more is read.
	HTTP2WindowUpdateChromium
)

// HTTP2Errors is how an HTTP/2 connection handles the errors of the
// server: frames, header blocks, settings or windows it does not accept.
type HTTP2Errors int

const (
	// HTTP2ErrorsGo handles them as Go: most close the connection with
	// GOAWAY, without debug data.
	HTTP2ErrorsGo HTTP2Errors = iota
	// HTTP2ErrorsChromium handles them as Chromium: those it takes as
	// connection errors close the connection with its GOAWAY code and
	// debug data, such as "Framer error: 1 (INVALID_STREAM_ID).", those
	// it takes as stream errors reset the stream, and those it ignores,
	// such as an invalid INITIAL_WINDOW_SIZE, are ignored. A connection
	// lost to PrefacePing is closed with GOAWAY "Failed ping.". As in
	// Chromium, at most 256 streams are open at once whatever
	// MAX_CONCURRENT_STREAMS says, and a first SETTINGS without it keeps
	// the initial limit of 100, where Go raises it to 1000.
	HTTP2ErrorsChromium
)

// HTTP2ALPS is how an HTTP/2 connection reads the ALPS of the server, the
// HTTP/2 frames the server sends in the TLS handshake when the ClientHello
// offers ALPS (application_settings) for h2.
type HTTP2ALPS int

const (
	// HTTP2ALPSIgnore ignores them, as Go, which has no ALPS.
	HTTP2ALPSIgnore HTTP2ALPS = iota
	// HTTP2ALPSChromium reads them as Chromium, before the first frame of
	// the server: their SETTINGS apply as those of a SETTINGS frame,
	// without ACK, and malformed ALPS, such as a frame other than SETTINGS
	// or ACCEPT_CH, closes the connection with GOAWAY PROTOCOL_ERROR
	// "Error parsing ALPS: N" and fails the request. ACCEPT_CH is not
	// used.
	HTTP2ALPSChromium
)

// HTTP2HeaderFraming is how a header block too large for one frame is cut
// into HEADERS and CONTINUATION frames.
type HTTP2HeaderFraming int

const (
	// HTTP2HeaderFramingGo fills each frame up to the MAX_FRAME_SIZE of
	// the server, as Go.
	HTTP2HeaderFramingGo HTTP2HeaderFraming = iota
	// HTTP2HeaderFramingChromium sends frames of at most 16383 bytes with
	// their 9-byte header, whatever the MAX_FRAME_SIZE of the server, as
	// Chromium.
	HTTP2HeaderFramingChromium
)

// HTTP2Settings is what a new HTTP/2 connection sends before its first
// request, how its requests announce their priority, how it sends DATA
// frames, header fields, PINGs, window updates and resets, and how it
// handles the errors of the server.
type HTTP2Settings struct {
	// Settings are sent exactly, in this order. Unknown IDs, such as
	// GREASE values, are sent as given. ENABLE_PUSH 0 is required: its
	// initial value, 1, would allow the server push the client refuses.
	Settings []HTTP2Setting
	// ConnectionWindowUpdate is the increment of the WINDOW_UPDATE sent on
	// the connection right after SETTINGS; 0 sends none.
	ConnectionWindowUpdate uint32
	// Priority is how the requests announce their priority.
	Priority HTTP2Priority
	// MaxDataFrameSize, if non-zero, limits the DATA frames of a request
	// body below the server's MAX_FRAME_SIZE: Chrome sends at most 16375
	// bytes, whatever the server allows.
	MaxDataFrameSize uint32
	// HPACK is how the header fields are encoded.
	HPACK HTTP2HPACK
	// PrefacePing, if non-zero, sends a PING right after the HEADERS of a
	// request, or a DATA frame with payload, when nothing has been read on
	// the connection for longer than it, as Chrome does after 10 s: at
	// most one at a time, with a payload counting the PINGs from 1. If
	// nothing is read for PrefacePing while it is unanswered, the
	// connection is closed as lost, and its requests fail.
	PrefacePing time.Duration
	// WindowUpdate is when the receive windows are given back.
	WindowUpdate HTTP2WindowUpdate
	// CancelWithoutPing sends the RST_STREAM of a cancelled request alone,
	// as Chrome. Otherwise, as in Go, when nothing has been read since the
	// request was sent, a PING goes with it, and the stream keeps its
	// place in the server's concurrency limit until the PING is answered.
	CancelWithoutPing bool
	// PriorityFrames are sent in order right after SETTINGS and the
	// connection WINDOW_UPDATE, as Firefox up to version 88 built its
	// priority tree on idle streams. Chrome sends none.
	PriorityFrames []HTTP2PriorityFrame
	// HeaderPriority is the priority of every HEADERS with
	// HTTP2PriorityFixed.
	HeaderPriority HTTP2PriorityParam
	// FirstStreamID, if non-zero, is the stream of the first request,
	// above the streams of PriorityFrames; 0 is 1.
	FirstStreamID uint32
	// Errors is how the errors of the server are handled.
	Errors HTTP2Errors
	// ALPS is how the ALPS of the server is read.
	ALPS HTTP2ALPS
	// HeaderFraming is how large header blocks are cut into frames.
	HeaderFraming HTTP2HeaderFraming
}

// WithHTTP2Settings sets the SETTINGS and the connection WINDOW_UPDATE of
// each new HTTP/2 connection. By default they are those of Chrome 156:
// HEADER_TABLE_SIZE 65536, ENABLE_PUSH 0, INITIAL_WINDOW_SIZE 6291456 and
// MAX_HEADER_LIST_SIZE 262144, then a WINDOW_UPDATE of 15663105, with
// HTTP2PriorityChromium, DATA frames of at most 16375 bytes,
// HTTP2HPACKChromium, a PrefacePing of 10 s, HTTP2WindowUpdateChromium,
// CancelWithoutPing, HTTP2ErrorsChromium, HTTP2ALPSChromium and
// HTTP2HeaderFramingChromium.
//
// The values announced are enforced: HEADER_TABLE_SIZE sizes the HPACK
// decoder, INITIAL_WINDOW_SIZE the receive window of each stream, the
// window update that of the connection (65535 plus it), MAX_FRAME_SIZE the
// largest frame read and MAX_HEADER_LIST_SIZE the response headers. One
// left out keeps its RFC 9113 initial value; without MAX_HEADER_LIST_SIZE
// the response headers are still limited to 256 KiB. Invalid settings
// return an error that wraps ErrConfig: a setting repeated, a value RFC
// 9113 forbids, ENABLE_PUSH left out or other than 0 (server push is
// refused, and its initial value is 1),
// INITIAL_WINDOW_SIZE or MAX_HEADER_LIST_SIZE of 0, a connection window
// above 2^31-1, an unknown Priority, HPACK, WindowUpdate, Errors, ALPS or
// HeaderFraming, a negative
// PrefacePing, a PRIORITY frame on stream 0 or on its own stream, a stream
// ID above 2^31-1, an even FirstStreamID, a HeaderPriority without
// HTTP2PriorityFixed or a zero one with it, or PriorityFrames,
// HTTP2PriorityFixed or
// HTTP2PriorityChromium with
// NO_RFC7540_PRIORITIES 1, which says the client sends no such priority.
// The settings are copied when WithHTTP2Settings is called.
func WithHTTP2Settings(s HTTP2Settings) Option {
	// Converted now: the Settings slice is the caller's.
	pre, err := h2Preface(s)
	return func(c *config) error {
		if err != nil {
			return fmt.Errorf("WithHTTP2Settings: %w", err)
		}
		c.h2 = pre
		return nil
	}
}

// h2Preface validates s and converts it for the transport.
func h2Preface(s HTTP2Settings) (*dispatch.H2Preface, error) {
	pre := &dispatch.H2Preface{
		Settings:          make([]http2.Setting, len(s.Settings)),
		ConnWindowUpdate:  s.ConnectionWindowUpdate,
		MaxDataFrameSize:  s.MaxDataFrameSize,
		PrefacePing:       s.PrefacePing,
		CancelWithoutPing: s.CancelWithoutPing,
	}
	if s.PrefacePing < 0 {
		return nil, fmt.Errorf("negative PrefacePing %v", s.PrefacePing)
	}
	for i, st := range s.Settings {
		pre.Settings[i] = http2.Setting{ID: http2.SettingID(st.ID), Val: st.Value}
	}
	if err := http2.CheckSettings(pre.Settings, pre.ConnWindowUpdate); err != nil {
		return nil, err
	}
	noRFC7540 := slices.Contains(pre.Settings, http2.Setting{ID: http2.SettingNoRFC7540Priorities, Val: 1})
	switch s.Priority {
	case HTTP2PriorityNone:
	case HTTP2PriorityChromium:
		if noRFC7540 {
			return nil, errors.New("HTTP2PriorityChromium with NO_RFC7540_PRIORITIES 1")
		}
		pre.PriorityChain = true
	case HTTP2PriorityFixed:
		if noRFC7540 {
			return nil, errors.New("HTTP2PriorityFixed with NO_RFC7540_PRIORITIES 1")
		}
		if s.HeaderPriority == (HTTP2PriorityParam{}) {
			return nil, errors.New("HTTP2PriorityFixed with a zero HeaderPriority, which sends no PRIORITY flag")
		}
		p := s.HeaderPriority.engine()
		pre.HeaderPriority = &p
	default:
		return nil, fmt.Errorf("unknown priority %d", s.Priority)
	}
	if s.Priority != HTTP2PriorityFixed && s.HeaderPriority != (HTTP2PriorityParam{}) {
		return nil, errors.New("HeaderPriority without HTTP2PriorityFixed")
	}
	if len(s.PriorityFrames) > 0 && noRFC7540 {
		return nil, errors.New("PriorityFrames with NO_RFC7540_PRIORITIES 1")
	}
	for _, f := range s.PriorityFrames {
		pre.PriorityFrames = append(pre.PriorityFrames, http2.PriorityFrameParam{StreamID: f.StreamID, PriorityParam: f.engine()})
	}
	pre.FirstStreamID = s.FirstStreamID
	if err := http2.CheckPriorities(pre.PriorityFrames, pre.HeaderPriority, pre.FirstStreamID); err != nil {
		return nil, err
	}
	switch s.HPACK {
	case HTTP2HPACKGo:
	case HTTP2HPACKChromium:
		pre.ChromiumHPACK = true
	default:
		return nil, fmt.Errorf("unknown HPACK %d", s.HPACK)
	}
	switch s.WindowUpdate {
	case HTTP2WindowUpdateGo:
	case HTTP2WindowUpdateChromium:
		pre.ChromiumWindowUpdate = true
	default:
		return nil, fmt.Errorf("unknown WindowUpdate %d", s.WindowUpdate)
	}
	switch s.Errors {
	case HTTP2ErrorsGo:
	case HTTP2ErrorsChromium:
		pre.ChromiumErrors = true
	default:
		return nil, fmt.Errorf("unknown Errors %d", s.Errors)
	}
	switch s.ALPS {
	case HTTP2ALPSIgnore:
	case HTTP2ALPSChromium:
		pre.ChromiumALPS = true
	default:
		return nil, fmt.Errorf("unknown ALPS %d", s.ALPS)
	}
	switch s.HeaderFraming {
	case HTTP2HeaderFramingGo:
	case HTTP2HeaderFramingChromium:
		pre.ChromiumHeaderFraming = true
	default:
		return nil, fmt.Errorf("unknown HeaderFraming %d", s.HeaderFraming)
	}
	return pre, nil
}
