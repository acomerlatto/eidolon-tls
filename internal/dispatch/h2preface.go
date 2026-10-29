package dispatch

import (
	"slices"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// H2Preface is what a new HTTP/2 connection sends before its first
// request: the SETTINGS, in order, and the increment of the WINDOW_UPDATE
// on the connection, 0 for none. It also says how the requests announce
// their priority and how the connection sends: PriorityChain,
// MaxDataFrameSize, ChromiumHPACK, PrefacePing, ChromiumWindowUpdate,
// CancelWithoutPing, PriorityFrames, HeaderPriority, FirstStreamID,
// ChromiumErrors, ChromiumALPS and ChromiumHeaderFraming are those of
// http2.Transport.
type H2Preface struct {
	Settings              []http2.Setting
	ConnWindowUpdate      uint32
	PriorityChain         bool
	MaxDataFrameSize      uint32
	ChromiumHPACK         bool
	PrefacePing           time.Duration
	ChromiumWindowUpdate  bool
	CancelWithoutPing     bool
	PriorityFrames        []http2.PriorityFrameParam
	HeaderPriority        *http2.PriorityParam
	FirstStreamID         uint32
	ChromiumErrors        bool
	ChromiumALPS          bool
	ChromiumHeaderFraming bool
}

// DefaultH2 is the preface of Chrome 156 (A10): a 64 KiB HPACK table, no
// server push, windows of 6 MiB per stream and 15 MiB per connection, a
// header list of 256 KiB, the priority chain of Chromium, DATA frames of
// at most 16375 bytes, the HPACK encoding of Chromium, its PING after 10 s
// without a read, its window updates, its RST_STREAM without PING, its
// handling of the errors of the server, its reading of the ALPS of the
// server, and its fragmenting of header blocks.
var DefaultH2 = H2Preface{
	Settings: []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	},
	ConnWindowUpdate:      15663105,
	PriorityChain:         true,
	MaxDataFrameSize:      16375,
	ChromiumHPACK:         true,
	PrefacePing:           10 * time.Second,
	ChromiumWindowUpdate:  true,
	CancelWithoutPing:     true,
	ChromiumErrors:        true,
	ChromiumALPS:          true,
	ChromiumHeaderFraming: true,
}

// defaultH2 returns DefaultH2 with maxHeaderList as MAX_HEADER_LIST_SIZE,
// so the limit announced is the one enforced.
func defaultH2(maxHeaderList uint32) *H2Preface {
	pre := DefaultH2
	pre.Settings = slices.Clone(pre.Settings)
	for i, s := range pre.Settings {
		if s.ID == http2.SettingMaxHeaderListSize {
			pre.Settings[i].Val = maxHeaderList
		}
	}
	return &pre
}

// defaultOrder closes the order chain of every request: the pseudo-headers
// of Chrome (A10), ":method", ":authority", ":scheme", ":path", after the
// ones the request or the client list.
var defaultOrder = &order.Order{Pseudo: []string{":method", ":authority", ":scheme", ":path"}}
