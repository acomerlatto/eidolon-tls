package http2

import (
	"encoding/binary"
	"time"
)

// prefacePing is the state of the preface PING of a connection
// (Transport.PrefacePing), under ClientConn.mu.
type prefacePing struct {
	id       uint64  // of the last PING sent
	data     [8]byte // payload of the PING in flight
	inFlight bool    // sent, not acknowledged
	checking bool    // a check of the PING pending
}

// readNow returns the time since cc was created, the clock of
// ClientConn.lastRead.
func (cc *ClientConn) readNow() time.Duration {
	return time.Since(cc.born)
}

// maybePrefacePing sends a PING, as Chromium's MaybeSendPrefacePing, if
// Transport.PrefacePing is set, nothing was read on cc for longer than it,
// and no PING is in flight or being checked. The payload counts the PINGs
// from 1. It is called with cc.wmu held, right after a HEADERS or a DATA
// frame with payload, which the PING follows on the wire.
func (cc *ClientConn) maybePrefacePing() {
	d := cc.t.PrefacePing
	if d == 0 {
		return
	}
	cc.mu.Lock()
	p := &cc.prefacePing
	if p.checking || cc.readNow() <= time.Duration(cc.lastRead.Load())+d {
		cc.mu.Unlock()
		return
	}
	p.id++
	binary.BigEndian.PutUint64(p.data[:], p.id)
	p.inFlight, p.checking = true, true
	data, sent := p.data, cc.readNow()
	cc.mu.Unlock()
	cc.fr.WritePing(false, data)
	time.AfterFunc(d, func() { cc.checkPrefacePing(sent) })
}

// checkPrefacePing checks the PING in flight as Chromium's
// CheckPingStatus, one PrefacePing after it was sent or after the last
// check, at last: once acknowledged, it is done; if nothing was read since
// then, or for PrefacePing, the connection is lost; otherwise it checks
// again one PrefacePing after the last read.
func (cc *ClientConn) checkPrefacePing(last time.Duration) {
	d := cc.t.PrefacePing
	cc.mu.Lock()
	p := &cc.prefacePing
	if !p.inFlight || cc.closed {
		p.checking = false
		cc.mu.Unlock()
		return
	}
	now, read := cc.readNow(), time.Duration(cc.lastRead.Load())
	if now > read+d || read < last {
		p.checking = false
		cc.mu.Unlock()
		cc.closeForLostPing()
		return
	}
	cc.mu.Unlock()
	time.AfterFunc(read+d-now, func() { cc.checkPrefacePing(now) })
}

// prefacePingAcked records the acknowledgment of a PING with data. cc.mu
// must be held.
func (cc *ClientConn) prefacePingAcked(data [8]byte) {
	if p := &cc.prefacePing; p.inFlight && data == p.data {
		p.inFlight = false
	}
}
