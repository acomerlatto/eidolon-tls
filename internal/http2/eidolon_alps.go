// The ALPS of the server as Chromium reads it (patches 0029 and 0036).

package http2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"strings"
)

// Errors of Chromium's AlpsDecoder::Decode, the N of the GOAWAY debug data
// "Error parsing ALPS: N".
const (
	alpsFramingError          = 1
	alpsForbiddenFrame        = 2
	alpsNotOnFrameBoundary    = 3
	alpsSettingsWithAck       = 4
	alpsAcceptChInvalidStream = 5
	alpsAcceptChWithFlags     = 6
)

// frameAcceptCH is the type of the ACCEPT_CH frame.
const frameAcceptCH FrameType = 0x89

// alpsConn is a connection that negotiated ALPS: PeerApplicationSettings
// returns the ALPS data of the server, nil without ALPS.
type alpsConn interface {
	PeerApplicationSettings() []byte
}

// decodeALPS reads data, the ALPS of the server, as Chromium's AlpsDecoder:
// HTTP/2 frames checked as quiche's decoder checks them, of which SETTINGS
// and ACCEPT_CH count. It returns the settings by order of ID, the last
// value of an ID winning (spdy::SettingsMap), or the number of the error,
// by the precedence of Decode: a framing error, which stops the decoding,
// then a forbidden frame, a SETTINGS ACK, data that ends inside a frame
// and an ACCEPT_CH off stream 0 or with flags. ACCEPT_CH is not kept.
func decodeALPS(data []byte) ([]Setting, int) {
	fr := NewFramer(io.Discard, bytes.NewReader(data))
	fr.chromium = true
	fr.SetMaxReadFrameSize(initialMaxFrameSize) // the default of quiche's decoder
	values := map[SettingID]uint32{}
	var forbidden, ack, boundary bool
	acceptCH := 0
	// framing reports a framing error of quiche's decoder.
	framing := func(err error) bool {
		var ce chromiumError
		return errors.As(err, &ce) && strings.HasPrefix(ce.Debug, "Framer error")
	}
	for {
		fh, err := fr.ReadFrameHeader()
		if err == io.EOF {
			break
		}
		if framing(err) {
			return nil, alpsFramingError
		}
		if err != nil {
			boundary = true
			break
		}
		switch fh.Type {
		case FrameData, FrameHeaders, FramePriority, FrameRSTStream, FramePushPromise,
			FramePing, FrameGoAway, FrameWindowUpdate, FrameContinuation:
			forbidden = true
		case frameAcceptCH:
			if acceptCH == 0 && fh.StreamID != 0 {
				acceptCH = alpsAcceptChInvalidStream
			} else if acceptCH == 0 && fh.Flags != 0 {
				acceptCH = alpsAcceptChWithFlags
			}
		}
		f, err := fr.ReadFrameForHeader(fh)
		if framing(err) {
			return nil, alpsFramingError
		}
		// io.EOF: the data ends right after the header.
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			boundary = true
			break
		}
		if sf, ok := f.(*SettingsFrame); ok {
			ack = ack || sf.IsAck()
			sf.ForeachSetting(func(s Setting) error {
				values[s.ID] = s.Val
				return nil
			})
		}
	}
	switch {
	case forbidden:
		return nil, alpsForbiddenFrame
	case ack:
		return nil, alpsSettingsWithAck
	case boundary:
		return nil, alpsNotOnFrameBoundary
	case acceptCH != 0:
		return nil, acceptCH
	}
	var settings []Setting
	for _, id := range slices.Sorted(maps.Keys(values)) {
		settings = append(settings, Setting{ID: id, Val: values[id]})
	}
	return settings, 0
}

// applyALPS reads the ALPS of the server on c, if any, as Chromium's
// SpdySession::ParseAlps, before the first frame of the server: each
// setting is handled as one of a SETTINGS frame, with no ACK; an error of
// decodeALPS, or of a setting, closes cc with the GOAWAY of Chromium.
func (cc *ClientConn) applyALPS(c net.Conn) error {
	ac, ok := c.(alpsConn)
	if !ok {
		return nil
	}
	settings, n := decodeALPS(ac.PeerApplicationSettings())
	var err error
	if n != 0 {
		err = chromiumError{ErrCodeProtocol, fmt.Sprintf("Error parsing ALPS: %d", n)}
	} else {
		cc.wmu.Lock()
		cc.mu.Lock()
		for _, s := range settings {
			var seenMax bool
			if seenMax, err = cc.applySetting(s); err != nil {
				break
			}
			cc.alpsMaxConcurrentStreams = cc.alpsMaxConcurrentStreams || seenMax
		}
		cc.mu.Unlock()
		cc.wmu.Unlock()
	}
	if err == nil {
		return nil
	}
	var ce chromiumError
	if !errors.As(err, &ce) {
		ce = chromiumError{ErrCodeProtocol, err.Error()}
	}
	cc.writeChromiumGoAway(ce)
	cc.tconn.Close()
	return ce
}
