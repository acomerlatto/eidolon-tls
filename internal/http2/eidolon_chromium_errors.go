// Errors of the server as Chromium reports them (patch 0028).

package http2

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/http2/hpack"
	"github.com/acomerlatto/eidolon-tls/internal/httpcommon"
	"golang.org/x/net/http/httpguts"
)

// chromiumError is a connection error as Chromium's DoDrainSession sends
// it: GOAWAY with Code and Debug as debug data. It unwraps to
// ConnectionError(Code).
type chromiumError struct {
	Code  ErrCode
	Debug string
}

func (e chromiumError) Error() string {
	return fmt.Sprintf("connection error: %s: %s", e.Code, e.Debug)
}

func (e chromiumError) Unwrap() error { return ConnectionError(e.Code) }

// framerError is a SpdyFramerError of quiche's Http2DecoderAdapter.
type framerError int

const (
	feInvalidStreamID         framerError = 1
	feInvalidControlFrame     framerError = 2
	feControlPayloadTooLarge  framerError = 3
	feInvalidPadding          framerError = 5
	feInvalidDataFrameFlags   framerError = 6
	feUnexpectedFrame         framerError = 7
	feInvalidControlFrameSize framerError = 9
	feOversizedPayload        framerError = 10
)

var framerErrorNames = map[framerError]string{
	feInvalidStreamID:         "INVALID_STREAM_ID",
	feInvalidControlFrame:     "INVALID_CONTROL_FRAME",
	feControlPayloadTooLarge:  "CONTROL_PAYLOAD_TOO_LARGE",
	feInvalidPadding:          "INVALID_PADDING",
	feInvalidDataFrameFlags:   "INVALID_DATA_FRAME_FLAGS",
	feUnexpectedFrame:         "UNEXPECTED_FRAME",
	feInvalidControlFrameSize: "INVALID_CONTROL_FRAME_SIZE",
	feOversizedPayload:        "OVERSIZED_PAYLOAD",
}

// err returns the connection error of e, as SpdySession::OnError: the
// code of MapFramerErrorToNetError, the debug data "Framer error: %d
// (%s).".
func (e framerError) err() error {
	code := ErrCodeProtocol
	switch e {
	case feControlPayloadTooLarge, feInvalidControlFrameSize, feOversizedPayload:
		code = ErrCodeFrameSize
	}
	return chromiumError{code, fmt.Sprintf("Framer error: %d (%s).", int(e), framerErrorNames[e])}
}

// hpackChromiumError returns the connection error of an error of the
// HPACK decoder with SetQuicheErrors: COMPRESSION_ERROR.
func hpackChromiumError(err error) error {
	var qe hpack.QuicheError
	if errors.As(err, &qe) {
		return chromiumError{ErrCodeCompression, fmt.Sprintf("Framer error: %d (%s).", int(qe), qe.Name())}
	}
	return ConnectionError(ErrCodeCompression)
}

// quicheKnownFrame reports whether quiche decodes frames of type t, as
// IsSupportedHttp2FrameType: up to ALTSVC, and PRIORITY_UPDATE.
func quicheKnownFrame(t FrameType) bool {
	return t <= 0xa || t == FramePriorityUpdate
}

// chromiumHeaderError checks the header of a frame as quiche's
// Http2DecoderAdapter::OnFrameHeader, Http2FrameDecoder and
// OnContinuationStart, in their order, and tracks the header blocks,
// PUSH_PROMISE included, that CONTINUATION frames go on.
func (fr *Framer) chromiumHeaderError(fh FrameHeader) error {
	expecting := fr.lastHeaderStream != 0
	if expecting && fh.Type != FrameContinuation {
		return feUnexpectedFrame.err()
	}
	if !quicheKnownFrame(fh.Type) {
		if fr.unknownStreamOK != nil && !fr.unknownStreamOK(fh.StreamID) {
			return feInvalidControlFrame.err()
		}
	} else {
		switch fh.Type {
		case FrameData, FrameHeaders, FramePriority, FrameRSTStream, FrameContinuation, FramePushPromise:
			if fh.StreamID == 0 {
				return feInvalidStreamID.err()
			}
		case FrameGoAway, FrameSettings, FramePing:
			if fh.StreamID != 0 {
				return feInvalidStreamID.err()
			}
		}
		if !expecting && fh.Type == FrameContinuation {
			return feUnexpectedFrame.err()
		}
		if fh.Type == FrameData && fh.Flags&^(FlagDataEndStream|FlagDataPadded) != 0 {
			return feInvalidDataFrameFlags.err()
		}
	}
	if fh.Length > fr.maxReadSize {
		if fh.Type == FrameData {
			return feOversizedPayload.err()
		}
		return feControlPayloadTooLarge.err()
	}
	switch fh.Type {
	case FrameContinuation:
		if fh.StreamID != fr.lastHeaderStream {
			return feUnexpectedFrame.err()
		}
		fallthrough
	case FrameHeaders, FramePushPromise:
		if fh.Flags.Has(FlagHeadersEndHeaders) {
			fr.lastHeaderStream = 0
		} else {
			fr.lastHeaderStream = fh.StreamID
		}
	}
	return nil
}

// chromiumPayloadError checks the payload of a frame as quiche's payload
// decoders, and the WINDOW_UPDATE increment as SpdySession::OnWindowUpdate:
// 0 on the connection is a connection error, on a stream a stream error
// with FLOW_CONTROL_ERROR.
func (fr *Framer) chromiumPayloadError(fh FrameHeader, p []byte) error {
	// padded checks the padding: the pad length byte and the padding fit
	// in the payload, with need bytes more.
	padded := func(padded bool, need int) error {
		pad := 0
		if padded {
			if len(p) == 0 {
				if fh.Type == FrameData {
					return feInvalidDataFrameFlags.err()
				}
				return feInvalidPadding.err()
			}
			pad = 1 + int(p[0])
			if pad > len(p) {
				return feInvalidPadding.err()
			}
		}
		if len(p)-pad < need {
			return feInvalidControlFrameSize.err()
		}
		return nil
	}
	switch fh.Type {
	case FrameData:
		return padded(fh.Flags.Has(FlagDataPadded), 0)
	case FrameHeaders:
		need := 0
		if fh.Flags.Has(FlagHeadersPriority) {
			need = 5
		}
		return padded(fh.Flags.Has(FlagHeadersPadded), need)
	case FramePushPromise:
		if err := padded(fh.Flags.Has(FlagPushPromisePadded), 4); err != nil {
			return err
		}
		i := 0
		if fh.Flags.Has(FlagPushPromisePadded) {
			i = 1
		}
		if uint32(p[i])&0x7f|uint32(p[i+1])|uint32(p[i+2])|uint32(p[i+3]) == 0 {
			return feInvalidControlFrame.err()
		}
	case FramePriority:
		if len(p) != 5 {
			return feInvalidControlFrameSize.err()
		}
	case FrameRSTStream, FrameWindowUpdate:
		if len(p) != 4 {
			return feInvalidControlFrameSize.err()
		}
		if fh.Type == FrameWindowUpdate && (uint32(p[0])&0x7f|uint32(p[1])|uint32(p[2])|uint32(p[3])) == 0 {
			if fh.StreamID == 0 {
				return chromiumError{ErrCodeProtocol, "Received WINDOW_UPDATE with an invalid delta_window_size 0"}
			}
			return StreamError{StreamID: fh.StreamID, Code: ErrCodeFlowControl, Cause: errors.New("Received WINDOW_UPDATE with an invalid delta_window_size.")}
		}
	case FrameSettings:
		if fh.Flags.Has(FlagSettingsAck) && len(p) > 0 || len(p)%6 != 0 {
			return feInvalidControlFrameSize.err()
		}
	case FramePing:
		if len(p) != 8 {
			return feInvalidControlFrameSize.err()
		}
	case FrameGoAway:
		if len(p) < 8 {
			return feInvalidControlFrame.err()
		}
	case FramePriorityUpdate:
		if len(p) < 4 {
			return feInvalidControlFrameSize.err()
		}
		if fh.StreamID != 0 || (uint32(p[0])&0x7f|uint32(p[1])|uint32(p[2])|uint32(p[3])) == 0 {
			return feInvalidStreamID.err()
		}
	case 0xa: // ALTSVC: the origin length, then the origin
		if len(p) < 2 || int(p[0])<<8|int(p[1]) > len(p)-2 {
			return feInvalidControlFrame.err()
		}
	}
	return nil
}

// parseSettingsChromium parses a SETTINGS frame that chromiumPayloadError
// accepted, with the values Go refuses and Chromium ignores or refuses
// itself (ClientConn.chromiumSetting).
func parseSettingsChromium(_ *frameCache, fh FrameHeader, _ func(string), p []byte) (Frame, error) {
	return &SettingsFrame{FrameHeader: fh, p: p}, nil
}

// readMetaFrameChromium is readMetaFrame as Chromium: the whole block is
// decoded, and an invalid field in it is a stream error with
// PROTOCOL_ERROR, the only one the Framer returns with ChromiumErrors.
// Pseudo-header fields other than :status, which Chromium drops, are
// left to the transport, which only reads :status.
func (fr *Framer) readMetaFrameChromium(hf *HeadersFrame) (Frame, error) {
	mh := &MetaHeadersFrame{HeadersFrame: hf}
	fields, invalid, err := fr.readBlockChromium(hf)
	if err != nil {
		return nil, err
	}
	mh.HeadersFrame.headerFragBuf = nil
	mh.HeadersFrame.invalidate()
	if invalid != nil {
		return nil, StreamError{mh.StreamID, ErrCodeProtocol, invalid}
	}
	mh.Fields = fields
	return mh, nil
}

// readPushPromiseChromium decodes the header block of a PUSH_PROMISE, as
// Chromium does before refusing it with the connection.
func (fr *Framer) readPushPromiseChromium(pp *PushPromiseFrame) error {
	_, invalid, err := fr.readBlockChromium(pp)
	if err != nil {
		return err
	}
	if invalid != nil {
		return StreamError{pp.StreamID, ErrCodeProtocol, invalid}
	}
	return chromiumError{ErrCodeProtocol, "PUSH_PROMISE received"}
}

// readBlockChromium reads the header block that starts with first and its
// CONTINUATION frames, and decodes all of it. Its fields go through
// chromiumFieldError, whose first error is invalid; an HPACK error is a
// connection error.
func (fr *Framer) readBlockChromium(first headersOrContinuation) (fields []hpack.HeaderField, invalid, err error) {
	hdec := fr.ReadMetaHeaders
	hdec.SetEmitEnabled(true)
	hdec.SetMaxStringLength(fr.maxHeaderStringLen())
	var size uint64
	regular := false
	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		if invalid == nil {
			if invalid = chromiumFieldError(hf, &regular, &size, uint64(fr.maxHeaderListSize())); invalid == nil {
				fields = append(fields, hf)
			}
		}
	})
	defer hdec.SetEmitFunc(func(hpack.HeaderField) {})
	for hc := first; ; {
		if _, err := hdec.Write(hc.HeaderBlockFragment()); err != nil {
			return nil, nil, hpackChromiumError(err)
		}
		if hc.HeadersEnded() {
			break
		}
		f, err := fr.ReadFrame()
		if err != nil {
			return nil, nil, err
		}
		hc = f.(*ContinuationFrame)
	}
	if err := hdec.Close(); err != nil {
		return nil, nil, hpackChromiumError(err)
	}
	return fields, invalid, nil
}

// chromiumFieldError checks a field as Chromium's HeaderCoalescer: the
// name, with the pseudo-header fields first, the size of the list so far
// in size, against max, and the value.
func chromiumFieldError(hf hpack.HeaderField, regular *bool, size *uint64, max uint64) error {
	name := hf.Name
	if name == "" {
		return errors.New("Header name must not be empty.")
	}
	if name[0] == ':' {
		if *regular {
			return errors.New("Pseudo header must not follow regular headers.")
		}
		name = name[1:]
	} else {
		*regular = true
	}
	if !httpguts.ValidHeaderFieldName(name) {
		return errors.New("Invalid character in header name.")
	}
	if strings.ContainsFunc(name, func(r rune) bool { return 'A' <= r && r <= 'Z' }) {
		return errors.New("Upper case characters in header name.")
	}
	if *size += uint64(hf.Size()); *size > max {
		return errResponseHeaderListSize
	}
	for _, c := range []byte(hf.Value) {
		if c < '\t' || '\t' < c && c < 0x20 || c == 0x7f {
			return fmt.Errorf("Invalid character 0x%02X in header value.", c)
		}
	}
	return nil
}

// chromiumMaxConcurrentStreams is the most streams Chromium opens at
// once on a connection, whatever MAX_CONCURRENT_STREAMS says
// (kMaxConcurrentStreamLimit).
const chromiumMaxConcurrentStreams = 256

// chromiumSettings is what Chromium keeps of the SETTINGS of the server
// (SpdySession::HandleSetting).
type chromiumSettings struct {
	seenSettings    bool // a SETTINGS frame has ended
	connectProtocol bool // ENABLE_CONNECT_PROTOCOL 1 was received
	noRFC7540       bool // NO_RFC7540_PRIORITIES 1 in the first SETTINGS
}

// chromiumSetting handles s as SpdySession::HandleSetting, with cc.mu
// held: ignore reports a value Chromium drops, err a connection error.
// The other values are applied as in Go.
func (cc *ClientConn) chromiumSetting(s Setting) (ignore bool, err error) {
	c := &cc.chromium
	switch s.ID {
	case SettingMaxFrameSize:
		return s.Val < minMaxFrameSize || s.Val > maxFrameSize, nil
	case SettingInitialWindowSize:
		if s.Val > maxFlowWindow {
			return true, nil
		}
		if int64(s.Val) > int64(cc.flow.initial) {
			for _, id := range slices.Sorted(maps.Keys(cc.streams)) {
				if int64(s.Val)+int64(cc.streams[id].flow.delta) > maxFlowWindow {
					return false, chromiumError{ErrCodeFlowControl, fmt.Sprintf("New spdy::SETTINGS_INITIAL_WINDOW_SIZE value overflows flow control window of stream %d.", id)}
				}
			}
		}
	case SettingEnableConnectProtocol:
		if s.Val > 1 || c.connectProtocol && s.Val == 0 {
			return false, chromiumError{ErrCodeProtocol, "Invalid value for spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL."}
		}
		c.connectProtocol = c.connectProtocol || s.Val == 1
	case SettingNoRFC7540Priorities:
		if s.Val > 1 {
			return false, chromiumError{ErrCodeProtocol, "Invalid value for spdy::SETTINGS_DEPRECATE_HTTP2_PRIORITIES."}
		}
		if c.seenSettings && (s.Val == 1) != c.noRFC7540 {
			return false, chromiumError{ErrCodeProtocol, "spdy::SETTINGS_DEPRECATE_HTTP2_PRIORITIES value changed after first SETTINGS frame."}
		}
		c.noRFC7540 = c.noRFC7540 || !c.seenSettings && s.Val == 1
	}
	return false, nil
}

// writeChromiumGoAway sends the GOAWAY of e, as DoDrainSession, waiting
// for it at most as long as goAwayAndClose.
func (cc *ClientConn) writeChromiumGoAway(e chromiumError) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		cc.wmu.Lock()
		defer cc.wmu.Unlock()
		cc.fr.WriteGoAway(0, e.Code, []byte(e.Debug))
		cc.bw.Flush()
	}()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
	}
}

// unknownStreamOK is SpdySession::OnUnknownFrame: a frame of an unknown
// type may be on the connection, or on a stream opened so far.
func (cc *ClientConn) unknownStreamOK(id uint32) bool {
	if id%2 == 0 {
		return id == 0
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.nextStreamID != cc.firstStreamID && id < cc.nextStreamID
}

// chromiumStatusError checks the :status of response headers as
// SpdyStream::OnHeadersReceived: Chromium joins repeated fields, and
// cannot parse such a status. Go refuses a missing one itself.
func chromiumStatusError(f *MetaHeadersFrame) error {
	n := 0
	for _, hf := range f.PseudoFields() {
		if hf.Name == ":status" {
			n++
		}
	}
	if n > 1 {
		return errors.New("Cannot parse :status.")
	}
	return nil
}

// processTrailersChromium takes a header block after the response headers
// as SpdyStream::OnHeadersReceived: once, as trailers, with or without
// END_STREAM. Another one resets the stream.
func (rl *clientConnReadLoop) processTrailersChromium(cs *clientStream, f *MetaHeadersFrame) error {
	if cs.pastTrailers {
		rl.endStreamError(cs, StreamError{cs.ID, ErrCodeProtocol, errors.New("Header block received after trailers.")})
		return nil
	}
	cs.pastTrailers = true
	trailer := make(http.Header)
	for _, hf := range f.RegularFields() {
		key := httpcommon.CanonicalHeader(hf.Name)
		trailer[key] = append(trailer[key], hf.Value)
	}
	cs.trailer = trailer
	if f.StreamEnded() {
		rl.endStream(cs)
	}
	return nil
}

// chromiumRecvWindowError checks a DATA frame against the receive window
// of the connection as the server knows it, avail, as Chromium's
// DecreaseRecvWindowSize, called for the pad length, the data and the
// padding in turn.
func chromiumRecvWindowError(f *DataFrame, avail int32) error {
	data := int32(len(f.Data()))
	parts := []int32{data, int32(f.Length) - data}
	if f.Flags.Has(FlagDataPadded) {
		parts = []int32{1, data, int32(f.Length) - data - 1}
	}
	for _, n := range parts {
		if n == 0 {
			continue
		}
		if n > avail {
			return chromiumError{ErrCodeFlowControl, fmt.Sprintf("delta_window_size is %d in DecreaseRecvWindowSize, which is larger than the receive window size of %d", n, avail)}
		}
		avail -= n
	}
	return nil
}

// checkDataChromium handles a DATA frame as Chromium before its stream
// takes it: the connection window is charged first
// (SpdySession::OnStreamFrameData), then the stream checks it
// (SpdyStream::OnDataReceived), which only data or END_STREAM reach. It
// reports done for a frame the stream does not take, whose connection
// window goes back, with the stream reset if it was an error. A stream
// whose response has ended is left to Go, which resets it with NO_ERROR
// if its request is still being sent.
func (rl *clientConnReadLoop) checkDataChromium(f *DataFrame) (done bool, err error) {
	cc := rl.cc
	cc.mu.Lock()
	if err := chromiumRecvWindowError(f, cc.inflow.avail); err != nil {
		cc.mu.Unlock()
		return true, err
	}
	cs := rl.streamByIDLocked(f.StreamID, headerOrDataFrame)
	data := len(f.Data()) > 0
	touches := data || f.StreamEnded()
	var serr error
	switch {
	case cs == nil:
	case !cs.pastHeaders:
		if touches {
			serr = StreamError{f.StreamID, ErrCodeProtocol, errors.New("DATA received before headers.")}
		}
	case cs.pastTrailers && data:
		serr = StreamError{f.StreamID, ErrCodeProtocol, errors.New("DATA received after trailers.")}
	case f.Length > uint32(cs.inflow.avail):
		serr = StreamError{f.StreamID, ErrCodeFlowControl, fmt.Errorf("DATA of %d bytes over the stream window of %d", f.Length, cs.inflow.avail)}
	default:
		cc.mu.Unlock()
		return false, nil
	}
	var connAdd int32
	if f.Length > 0 {
		cc.inflow.take(f.Length)
		connAdd = cc.inflow.add(int(f.Length))
	}
	cc.mu.Unlock()
	if connAdd > 0 {
		cc.wmu.Lock()
		cc.fr.WriteWindowUpdate(0, uint32(connAdd))
		cc.bw.Flush()
		cc.wmu.Unlock()
	}
	if serr != nil {
		rl.endStreamError(cs, serr)
	}
	return true, nil
}
