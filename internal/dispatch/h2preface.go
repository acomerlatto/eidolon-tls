package dispatch

import (
	"slices"

	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// H2Preface is what a new HTTP/2 connection sends before its first
// request: the SETTINGS, in order, and the increment of the WINDOW_UPDATE
// on the connection, 0 for none. It also says how the requests announce
// their priority: PriorityChain is http2.Transport.PriorityChain.
type H2Preface struct {
	Settings         []http2.Setting
	ConnWindowUpdate uint32
	PriorityChain    bool
}

// DefaultH2 is the preface of Chrome 156 (A10): a 64 KiB HPACK table, no
// server push, windows of 6 MiB per stream and 15 MiB per connection, a
// header list of 256 KiB, and the priority chain of Chromium.
var DefaultH2 = H2Preface{
	Settings: []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	},
	ConnWindowUpdate: 15663105,
	PriorityChain:    true,
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
