package eidolon

import (
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

// HTTP2Settings is what a new HTTP/2 connection sends before its first
// request.
type HTTP2Settings struct {
	// Settings are sent exactly, in this order. Unknown IDs, such as
	// GREASE values, are sent as given.
	Settings []HTTP2Setting
	// ConnectionWindowUpdate is the increment of the WINDOW_UPDATE sent on
	// the connection right after SETTINGS; 0 sends none.
	ConnectionWindowUpdate uint32
}

// WithHTTP2Settings sets the SETTINGS and the connection WINDOW_UPDATE of
// each new HTTP/2 connection. By default they are those of Chrome 156:
// HEADER_TABLE_SIZE 65536, ENABLE_PUSH 0, INITIAL_WINDOW_SIZE 6291456 and
// MAX_HEADER_LIST_SIZE 262144, then a WINDOW_UPDATE of 15663105.
//
// The values announced are enforced: HEADER_TABLE_SIZE sizes the HPACK
// decoder, INITIAL_WINDOW_SIZE the receive window of each stream, the
// window update that of the connection (65535 plus it), MAX_FRAME_SIZE the
// largest frame read and MAX_HEADER_LIST_SIZE the response headers. One
// left out keeps its RFC 9113 initial value; without MAX_HEADER_LIST_SIZE
// the response headers are still limited to 256 KiB. Invalid settings
// return an error that wraps ErrConfig: a setting repeated, a value RFC
// 9113 forbids, ENABLE_PUSH other than 0 (server push is refused),
// INITIAL_WINDOW_SIZE or MAX_HEADER_LIST_SIZE of 0, or a connection window
// above 2^31-1.
func WithHTTP2Settings(s HTTP2Settings) Option {
	return func(c *config) error {
		pre := &dispatch.H2Preface{Settings: make([]http2.Setting, len(s.Settings)), ConnWindowUpdate: s.ConnectionWindowUpdate}
		for i, st := range s.Settings {
			pre.Settings[i] = http2.Setting{ID: http2.SettingID(st.ID), Val: st.Value}
		}
		if err := http2.CheckSettings(pre.Settings, pre.ConnWindowUpdate); err != nil {
			return err
		}
		c.h2 = pre
		return nil
	}
}
