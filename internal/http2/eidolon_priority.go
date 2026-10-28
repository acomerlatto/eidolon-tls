package http2

import (
	"net/http"
	"slices"

	"github.com/acomerlatto/eidolon-tls/internal/httpcommon"
)

// chainWeight is the HEADERS weight of each urgency, as Chromium's
// Spdy3PriorityToHttp2Weight, less one as sent on the wire.
var chainWeight = [8]uint8{255, 219, 182, 146, 109, 73, 36, 0}

// chainUrgency returns the urgency of req for the priority chain: the u of
// the priority field it sends (RFC 9218), 3 without one.
func chainUrgency(req *http.Request) uint8 {
	p, _ := parseRFC9218Priority(httpcommon.PriorityField(req.Context(), req.Header), false)
	return p.urgency
}

// chainAddLocked sets the priority cs sends in its HEADERS and adds it to
// the chain of cc, as Chromium's Http2PriorityDependencies: an exclusive
// dependency on the last open stream of the same urgency, or else of the
// closest more urgent one, or else on stream 0. cs.ID must be set.
func (cc *ClientConn) chainAddLocked(cs *clientStream) {
	u := cs.urgency
	cs.priority = PriorityParam{Exclusive: true, Weight: chainWeight[u]}
	for i := int(u); i >= 0; i-- {
		if l := cc.chain[i]; len(l) > 0 {
			cs.priority.StreamDep = l[len(l)-1]
			break
		}
	}
	cc.chain[u] = append(cc.chain[u], cs.ID)
}

// chainForgetLocked takes the stream id out of the chain of cc.
func (cc *ClientConn) chainForgetLocked(id uint32) {
	for u, l := range cc.chain {
		if i := slices.Index(l, id); i >= 0 {
			cc.chain[u] = slices.Delete(l, i, i+1)
			return
		}
	}
}
