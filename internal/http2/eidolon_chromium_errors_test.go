// Errors of the server as Chromium reports them (patch 0028).

package http2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/http2/hpack"
)

// errorServer is the server end of a connection with ChromiumErrors.
type errorServer struct {
	t    *testing.T
	cc   *ClientConn
	fr   *Framer
	seen chan string
	errs []chan error // of the requests, by stream
}

// newErrorServer returns a connection to tr, by default with the SETTINGS
// of Chrome (frames of 16384 bytes, header lists of 262144),
// whose server has sent its SETTINGS and read the client's preface. It
// runs in a synctest bubble.
func newErrorServer(t *testing.T, tr *Transport) *errorServer {
	return newErrorServerStart(t, tr, func(fr *Framer) { fr.WriteSettings() })
}

// newErrorServerStart is newErrorServer with the first frames of the
// server written by start.
func newErrorServerStart(t *testing.T, tr *Transport, start func(fr *Framer)) *errorServer {
	client, server := net.Pipe()
	s := &errorServer{t: t, fr: NewFramer(server, server), seen: make(chan string, 1024)}
	go func() {
		defer close(s.seen)
		defer server.Close()
		if _, err := io.ReadFull(server, make([]byte, len(ClientPreface))); err != nil {
			return
		}
		for {
			f, err := s.fr.ReadFrame()
			if err != nil {
				return
			}
			s.seen <- summarize(f)
		}
	}()
	if tr.Settings == nil {
		tr.Settings = chromeSettings
	}
	tr.ChromiumErrors = true
	cc, err := tr.newClientConn(client, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.cc = cc
	t.Cleanup(func() { cc.Close() })
	start(s.fr)
	synctest.Wait()
	s.frames()
	return s
}

// summarize describes a frame the client sent.
func summarize(f Frame) string {
	switch f := f.(type) {
	case *GoAwayFrame:
		return fmt.Sprintf("GOAWAY %v %q", f.ErrCode, f.DebugData())
	case *RSTStreamFrame:
		return fmt.Sprintf("RST_STREAM %d %v", f.StreamID, f.ErrCode)
	case *DataFrame:
		return fmt.Sprintf("DATA %d %d", f.StreamID, len(f.Data()))
	case *WindowUpdateFrame:
		return fmt.Sprintf("WINDOW_UPDATE %d %d", f.StreamID, f.Increment)
	case *PingFrame:
		if f.IsAck() {
			return "PING ACK"
		}
		return "PING"
	case *SettingsFrame:
		if f.IsAck() {
			return "SETTINGS ACK"
		}
		return "SETTINGS"
	}
	return fmt.Sprintf("%v %d", f.Header().Type, f.Header().StreamID)
}

// frames returns the frames the client sent since the last call.
func (s *errorServer) frames() []string {
	var got []string
	for {
		select {
		case f, ok := <-s.seen:
			if !ok {
				return got
			}
			got = append(got, f)
			continue
		default:
		}
		return got
	}
}

// request opens a stream with a GET, and returns the error of RoundTrip
// and, if read, of reading the response body; unread, the body gives no
// window back. Its HEADERS are read.
func (s *errorServer) request(read bool) <-chan error {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	done := make(chan error, 1)
	go func() {
		resp, err := s.cc.RoundTrip(req)
		if err == nil && read {
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		done <- err
	}()
	synctest.Wait()
	s.frames()
	return done
}

// raw writes a frame as is.
func (s *errorServer) raw(t FrameType, flags Flags, stream uint32, payload ...byte) {
	s.fr.WriteRawFrame(t, flags, stream, payload)
}

// status200 is the HPACK block of :status 200.
var status200 = []byte{0x88}

// block encodes fields, as name and value in turn, with HPACK.
func block(fields ...string) []byte {
	var b bytes.Buffer
	e := hpack.NewEncoder(&b)
	for i := 0; i < len(fields); i += 2 {
		e.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
	}
	return b.Bytes()
}

// u32 is v in 4 bytes.
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// The connection errors of Chromium: GOAWAY on stream 0 with its code and
// its debug data, the framer errors in the order quiche checks them.
func TestChromiumConnectionErrors(t *testing.T) {
	framer := func(n int, name string) string {
		code := ErrCodeProtocol
		switch n {
		case 3, 9, 10:
			code = ErrCodeFrameSize
		case 11, 12, 13, 14, 15, 16, 17, 19, 20, 21, 23, 24:
			code = ErrCodeCompression
		}
		return fmt.Sprintf("GOAWAY %v %q", code, fmt.Sprintf("Framer error: %d (%s).", n, name))
	}
	headers := func(s *errorServer, b []byte) { s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, b...) }
	for _, tt := range []struct {
		name string
		send func(s *errorServer)
		want string
	}{
		// Header of the frame.
		{"no CONTINUATION", func(s *errorServer) {
			s.raw(FrameHeaders, 0, 1, status200...)
			s.raw(FramePing, 0, 1, make([]byte, 8)...) // stream ID wrong too
		}, framer(7, "UNEXPECTED_FRAME")},
		{"unexpected CONTINUATION too large", func(s *errorServer) {
			s.raw(FrameContinuation, FlagContinuationEndHeaders, 1, make([]byte, 16385)...)
		}, framer(7, "UNEXPECTED_FRAME")},
		{"unexpected CONTINUATION", func(s *errorServer) { s.raw(FrameContinuation, FlagContinuationEndHeaders, 1, status200...) }, framer(7, "UNEXPECTED_FRAME")},
		{"CONTINUATION on stream 0", func(s *errorServer) {
			s.raw(FrameHeaders, 0, 1, status200...)
			s.raw(FrameContinuation, FlagContinuationEndHeaders, 0)
		}, framer(1, "INVALID_STREAM_ID")},
		{"CONTINUATION of another stream", func(s *errorServer) {
			s.raw(FrameHeaders, 0, 1, status200...)
			s.raw(FrameContinuation, FlagContinuationEndHeaders, 3)
		}, framer(7, "UNEXPECTED_FRAME")},
		{"unknown on an even stream", func(s *errorServer) { s.raw(0x20, 0, 2) }, framer(2, "INVALID_CONTROL_FRAME")},
		{"unknown on a stream not opened", func(s *errorServer) { s.raw(0x20, 0, 3) }, framer(2, "INVALID_CONTROL_FRAME")},
		{"DATA on stream 0", func(s *errorServer) { s.raw(FrameData, 0, 0) }, framer(1, "INVALID_STREAM_ID")},
		{"HEADERS on stream 0", func(s *errorServer) { s.raw(FrameHeaders, FlagHeadersEndHeaders, 0) }, framer(1, "INVALID_STREAM_ID")},
		{"PRIORITY on stream 0", func(s *errorServer) { s.raw(FramePriority, 0, 0, 1, 2) }, framer(1, "INVALID_STREAM_ID")},
		{"RST_STREAM on stream 0", func(s *errorServer) { s.raw(FrameRSTStream, 0, 0, 1) }, framer(1, "INVALID_STREAM_ID")},
		{"PUSH_PROMISE on stream 0", func(s *errorServer) { s.raw(FramePushPromise, FlagPushPromiseEndHeaders, 0) }, framer(1, "INVALID_STREAM_ID")},
		{"SETTINGS on stream 1", func(s *errorServer) { s.raw(FrameSettings, FlagSettingsAck, 1, 1) }, framer(1, "INVALID_STREAM_ID")},
		{"PING on stream 1", func(s *errorServer) { s.raw(FramePing, 0, 1, 1) }, framer(1, "INVALID_STREAM_ID")},
		{"GOAWAY on stream 1", func(s *errorServer) { s.raw(FrameGoAway, 0, 1, 1) }, framer(1, "INVALID_STREAM_ID")},
		{"DATA flags", func(s *errorServer) { s.raw(FrameData, 0x2, 1) }, framer(6, "INVALID_DATA_FRAME_FLAGS")},
		{"DATA too large", func(s *errorServer) { s.raw(FrameData, 0, 1, make([]byte, 16385)...) }, framer(10, "OVERSIZED_PAYLOAD")},
		{"PING too large", func(s *errorServer) { s.raw(FramePing, 0, 0, make([]byte, 16385)...) }, framer(3, "CONTROL_PAYLOAD_TOO_LARGE")},
		{"unknown too large", func(s *errorServer) { s.raw(0x20, 0, 0, make([]byte, 16385)...) }, framer(3, "CONTROL_PAYLOAD_TOO_LARGE")},
		// Payload.
		{"DATA padded empty", func(s *errorServer) { s.raw(FrameData, FlagDataPadded, 1) }, framer(6, "INVALID_DATA_FRAME_FLAGS")},
		{"DATA padding", func(s *errorServer) { s.raw(FrameData, FlagDataPadded, 1, 1) }, framer(5, "INVALID_PADDING")},
		{"HEADERS padded empty", func(s *errorServer) { s.raw(FrameHeaders, FlagHeadersPadded|FlagHeadersEndHeaders, 1) }, framer(5, "INVALID_PADDING")},
		{"HEADERS padding", func(s *errorServer) { s.raw(FrameHeaders, FlagHeadersPadded|FlagHeadersEndHeaders, 1, 2, 0x88) }, framer(5, "INVALID_PADDING")},
		{"HEADERS priority", func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersPadded|FlagHeadersPriority|FlagHeadersEndHeaders, 1, 1, 0, 0, 0, 0, 0)
		}, framer(9, "INVALID_CONTROL_FRAME_SIZE")},
		{"PRIORITY size", func(s *errorServer) { s.raw(FramePriority, 0, 1, 0, 0, 0, 0) }, framer(9, "INVALID_CONTROL_FRAME_SIZE")},
		{"RST_STREAM size", func(s *errorServer) { s.raw(FrameRSTStream, 0, 1, 0, 0, 0) }, framer(9, "INVALID_CONTROL_FRAME_SIZE")},
		{"WINDOW_UPDATE size", func(s *errorServer) { s.raw(FrameWindowUpdate, 0, 1, 0, 0, 1) }, framer(9, "INVALID_CONTROL_FRAME_SIZE")},
		{"SETTINGS ACK size", func(s *errorServer) { s.raw(FrameSettings, FlagSettingsAck, 0, make([]byte, 6)...) }, framer(9, "INVALID_CONTROL_FRAME_SIZE")},
		{"SETTINGS size", func(s *errorServer) { s.raw(FrameSettings, 0, 0, make([]byte, 5)...) }, framer(9, "INVALID_CONTROL_FRAME_SIZE")},
		{"PING size", func(s *errorServer) { s.raw(FramePing, 0, 0, make([]byte, 7)...) }, framer(9, "INVALID_CONTROL_FRAME_SIZE")},
		{"GOAWAY size", func(s *errorServer) { s.raw(FrameGoAway, 0, 0, make([]byte, 7)...) }, framer(2, "INVALID_CONTROL_FRAME")},
		{"PUSH_PROMISE padded empty", func(s *errorServer) { s.raw(FramePushPromise, FlagPushPromisePadded|FlagPushPromiseEndHeaders, 1) }, framer(5, "INVALID_PADDING")},
		{"PUSH_PROMISE size", func(s *errorServer) { s.raw(FramePushPromise, FlagPushPromiseEndHeaders, 1, 0, 0, 2) }, framer(9, "INVALID_CONTROL_FRAME_SIZE")},
		{"PUSH_PROMISE stream 0", func(s *errorServer) { s.raw(FramePushPromise, FlagPushPromiseEndHeaders, 1, 0x80, 0, 0, 0) }, framer(2, "INVALID_CONTROL_FRAME")},
		{"PRIORITY_UPDATE size", func(s *errorServer) { s.raw(FramePriorityUpdate, 0, 0, 0, 0, 1) }, framer(9, "INVALID_CONTROL_FRAME_SIZE")},
		{"PRIORITY_UPDATE on stream 1", func(s *errorServer) { s.raw(FramePriorityUpdate, 0, 1, 0, 0, 0, 1) }, framer(1, "INVALID_STREAM_ID")},
		{"PRIORITY_UPDATE of stream 0", func(s *errorServer) { s.raw(FramePriorityUpdate, 0, 0, 0x80, 0, 0, 0) }, framer(1, "INVALID_STREAM_ID")},
		{"ALTSVC size", func(s *errorServer) { s.raw(0xa, 0, 0, 0, 2, 'a') }, framer(2, "INVALID_CONTROL_FRAME")},
		// HPACK.
		{"index 0", func(s *errorServer) { headers(s, []byte{0x80}) }, framer(19, "HPACK_INVALID_INDEX")},
		{"index", func(s *errorServer) { headers(s, []byte{0xff, 0x00}) }, framer(19, "HPACK_INVALID_INDEX")},
		{"name index", func(s *errorServer) { headers(s, []byte{0x7f, 0x00, 0x01, 'a'}) }, framer(20, "HPACK_INVALID_NAME_INDEX")},
		{"value after a bad name index", func(s *errorServer) { headers(s, []byte{0x7f, 0x00, 0x81, 0xff}) }, framer(17, "HPACK_VALUE_HUFFMAN_ERROR")},
		{"index varint", func(s *errorServer) { headers(s, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0x0f}) }, framer(11, "HPACK_INDEX_VARINT_ERROR")},
		{"varint of 11 bytes", func(s *errorServer) {
			headers(s, []byte{0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00})
		}, framer(11, "HPACK_INDEX_VARINT_ERROR")},
		{"name length varint", func(s *errorServer) {
			headers(s, []byte{0x40, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02})
		}, framer(12, "HPACK_NAME_LENGTH_VARINT_ERROR")},
		{"value length varint", func(s *errorServer) {
			headers(s, []byte{0x40, 0x01, 'a', 0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02})
		}, framer(13, "HPACK_VALUE_LENGTH_VARINT_ERROR")},
		{"name too long", func(s *errorServer) { headers(s, []byte{0x40, 0x7f, 0x82, 0x80, 0x10}) }, framer(14, "HPACK_NAME_TOO_LONG")},
		{"value too long", func(s *errorServer) { headers(s, []byte{0x40, 0x01, 'a', 0x7f, 0x82, 0x80, 0x10}) }, framer(15, "HPACK_VALUE_TOO_LONG")},
		{"name Huffman", func(s *errorServer) { headers(s, []byte{0x40, 0x81, 0x00, 0x01, 'a'}) }, framer(16, "HPACK_NAME_HUFFMAN_ERROR")},
		{"value Huffman", func(s *errorServer) { headers(s, []byte{0x40, 0x01, 'a', 0x81, 0x00}) }, framer(17, "HPACK_VALUE_HUFFMAN_ERROR")},
		{"size update after a field", func(s *errorServer) { headers(s, []byte{0x88, 0x20}) }, framer(21, "HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED")},
		{"third size update", func(s *errorServer) { headers(s, []byte{0x20, 0x20, 0x20, 0x88}) }, framer(21, "HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED")},
		{"size update too large", func(s *errorServer) {
			headers(s, []byte{0x3f, 0xe2, 0xff, 0x03, 0x88}) // 65537
		}, framer(23, "HPACK_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_ACKNOWLEDGED_SETTING")},
		{"truncated", func(s *errorServer) { headers(s, []byte{0x40, 0x05, 'a'}) }, framer(24, "HPACK_TRUNCATED_BLOCK")},
		{"truncated over CONTINUATION", func(s *errorServer) {
			s.raw(FrameHeaders, 0, 1, 0x40, 0x05)
			s.raw(FrameContinuation, FlagContinuationEndHeaders, 1, 'a')
		}, framer(24, "HPACK_TRUNCATED_BLOCK")},
		// SpdySession.
		{"PUSH_PROMISE", func(s *errorServer) {
			s.raw(FramePushPromise, 0, 1, append(u32(2), block(":method", "GET")...)...)
			s.raw(FrameContinuation, FlagContinuationEndHeaders, 1, block(":path", "/")...)
		}, `GOAWAY PROTOCOL_ERROR "PUSH_PROMISE received"`},
		{"PUSH_PROMISE with a bad block", func(s *errorServer) {
			s.raw(FramePushPromise, FlagPushPromiseEndHeaders, 1, append(u32(2), 0x80)...)
		}, framer(19, "HPACK_INVALID_INDEX")},
		{"connection WINDOW_UPDATE 0", func(s *errorServer) { s.raw(FrameWindowUpdate, 0, 0, u32(1<<31)...) }, `GOAWAY PROTOCOL_ERROR "Received WINDOW_UPDATE with an invalid delta_window_size 0"`},
		{"connection WINDOW_UPDATE overflow", func(s *errorServer) {
			s.raw(FrameWindowUpdate, 0, 0, u32(1<<31-1-65535)...)
			s.raw(FrameWindowUpdate, 0, 0, u32(1)...)
		}, `GOAWAY PROTOCOL_ERROR "Received WINDOW_UPDATE [delta: 1] for session overflows session_send_window_size_ [current: 2147483647]"`},
		{"PING ACK", func(s *errorServer) { s.raw(FramePing, FlagPingAck, 0, make([]byte, 8)...) }, `GOAWAY PROTOCOL_ERROR "Unexpected PING ACK."`},
		{"ENABLE_CONNECT_PROTOCOL 2", func(s *errorServer) {
			s.fr.WriteSettings(Setting{SettingEnableConnectProtocol, 2})
		}, `GOAWAY PROTOCOL_ERROR "Invalid value for spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL."`},
		{"ENABLE_CONNECT_PROTOCOL 0 after 1", func(s *errorServer) {
			s.fr.WriteSettings(Setting{SettingEnableConnectProtocol, 1})
			s.fr.WriteSettings(Setting{SettingEnableConnectProtocol, 0})
		}, `GOAWAY PROTOCOL_ERROR "Invalid value for spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL."`},
		{"NO_RFC7540_PRIORITIES 2", func(s *errorServer) {
			s.fr.WriteSettings(Setting{SettingNoRFC7540Priorities, 2})
		}, `GOAWAY PROTOCOL_ERROR "Invalid value for spdy::SETTINGS_DEPRECATE_HTTP2_PRIORITIES."`},
		{"NO_RFC7540_PRIORITIES changed", func(s *errorServer) {
			s.fr.WriteSettings(Setting{SettingNoRFC7540Priorities, 1})
		}, `GOAWAY PROTOCOL_ERROR "spdy::SETTINGS_DEPRECATE_HTTP2_PRIORITIES value changed after first SETTINGS frame."`},
		{"INITIAL_WINDOW_SIZE overflow", func(s *errorServer) {
			s.raw(FrameWindowUpdate, 0, 1, u32(1<<31-1-65535)...)
			s.fr.WriteSettings(Setting{SettingInitialWindowSize, 65536})
		}, `GOAWAY FLOW_CONTROL_ERROR "New spdy::SETTINGS_INITIAL_WINDOW_SIZE value overflows flow control window of stream 1."`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newErrorServer(t, &Transport{})
				done := s.request(true)
				tt.send(s)
				synctest.Wait()
				got := s.frames()
				if len(got) == 0 || got[len(got)-1] != tt.want {
					t.Errorf("frames %q, want last %q", got, tt.want)
				}
				if !s.cc.State().Closed {
					t.Error("connection open")
				}
				if err := <-done; !errors.As(err, new(ConnectionError)) {
					t.Errorf("request: %v, want a ConnectionError", err)
				}
			})
		})
	}
}

// DATA over the connection window, which the server knows as 65535 +
// 16381, is a connection error once a part of it, the pad length, the
// data or the padding, goes over: after 4 DATA frames of 16384 bytes,
// 16380 are left, one short of the data after the pad length.
func TestChromiumConnectionWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newErrorServer(t, &Transport{ConnWindowUpdate: 16381})
		s.request(false) // the body gives no window back
		s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, status200...)
		for range 4 {
			s.raw(FrameData, 0, 1, make([]byte, 16384)...)
		}
		s.raw(FrameData, FlagDataPadded, 1, append([]byte{3}, make([]byte, 16383)...)...)
		synctest.Wait()
		got := s.frames()
		want := `GOAWAY FLOW_CONTROL_ERROR "delta_window_size is 16380 in DecreaseRecvWindowSize, which is larger than the receive window size of 16379"`
		if len(got) == 0 || got[len(got)-1] != want {
			t.Errorf("frames %q, want last %q", got, want)
		}
	})
}

// DATA over the window of its stream, but not of the connection, resets
// the stream with FLOW_CONTROL_ERROR; the connection window goes back.
func TestChromiumStreamWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newErrorServer(t, &Transport{Settings: []Setting{{ID: SettingInitialWindowSize, Val: 20000}}})
		s.request(false) // the body gives no window back
		s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, status200...)
		s.raw(FrameData, 0, 1, make([]byte, 16384)...)
		s.raw(FrameData, 0, 1, make([]byte, 16384)...)
		synctest.Wait()
		want := []string{"WINDOW_UPDATE 0 16384", "RST_STREAM 1 FLOW_CONTROL_ERROR"}
		if got := s.frames(); !slices.Equal(got, want) {
			t.Errorf("frames %q, want %q", got, want)
		}
		if s.cc.State().Closed {
			t.Error("connection closed")
		}
	})
}

// What Go takes as a connection error and Chromium ignores: the
// connection goes on, and the request is answered.
func TestChromiumIgnored(t *testing.T) {
	for _, tt := range []struct {
		name string
		send func(s *errorServer)
	}{
		{"SETTINGS ACK", func(s *errorServer) {
			s.raw(FrameSettings, FlagSettingsAck, 0)
			s.raw(FrameSettings, FlagSettingsAck, 0)
		}},
		{"INITIAL_WINDOW_SIZE over 2^31-1", func(s *errorServer) { s.fr.WriteSettings(Setting{SettingInitialWindowSize, 1 << 31}) }},
		{"ENABLE_PUSH 2", func(s *errorServer) { s.fr.WriteSettings(Setting{SettingEnablePush, 2}) }},
		{"MAX_FRAME_SIZE 1", func(s *errorServer) { s.fr.WriteSettings(Setting{SettingMaxFrameSize, 1}) }},
		{"DATA on a stream not opened", func(s *errorServer) { s.raw(FrameData, 0, 5, 'x') }},
		{"unknown on stream 1", func(s *errorServer) { s.raw(0x20, 0, 1) }},
		{"ALTSVC", func(s *errorServer) { s.raw(0xa, 0, 0, 0, 0) }},
		{"ALTSVC on stream 2", func(s *errorServer) { s.raw(0xa, 0, 2, 0, 0) }},
		{"empty DATA before HEADERS", func(s *errorServer) { s.raw(FrameData, 0, 1) }},
		{"trailers", func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, status200...)
			s.raw(FrameHeaders, FlagHeadersEndHeaders|FlagHeadersEndStream, 1, block("a", "b")...)
		}},
		{"PRIORITY_UPDATE", func(s *errorServer) { s.raw(FramePriorityUpdate, 0, 0, 0, 0, 0, 1) }},
		{"RST_STREAM of a stream not opened", func(s *errorServer) { s.raw(FrameRSTStream, 0, 5, 0, 0, 0, 1) }},
		{"WINDOW_UPDATE 0 of a stream not opened", func(s *errorServer) { s.raw(FrameWindowUpdate, 0, 5, 0, 0, 0, 0) }},
		{"unknown pseudo-header", func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block(":status", "200", ":path", "/", ":foo", "x")...)
			s.raw(FrameData, FlagDataEndStream, 1, 'x')
		}},
		{"trailers without END_STREAM", func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, status200...)
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block(":status", "500", "a", "b")...)
			s.raw(FrameData, FlagDataEndStream, 1)
		}},
		{"trailers after END_STREAM", func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders|FlagHeadersEndStream, 1, status200...)
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block("a", "b")...)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newErrorServer(t, &Transport{})
				done := s.request(true)
				tt.send(s)
				s.raw(FrameHeaders, FlagHeadersEndHeaders|FlagHeadersEndStream, 1, status200...)
				synctest.Wait()
				if err := <-done; err != nil {
					t.Errorf("request: %v", err)
				}
				for _, f := range s.frames() {
					if strings.HasPrefix(f, "GOAWAY") || strings.HasPrefix(f, "RST_STREAM") {
						t.Errorf("sent %s", f)
					}
				}
				if s.cc.State().Closed {
					t.Error("connection closed")
				}
			})
		})
	}
}

// What Chromium resets the stream for, with the connection going on.
func TestChromiumStreamErrors(t *testing.T) {
	big := strings.Repeat("v", 140000)
	for _, tt := range []struct {
		name   string
		stream uint32
		send   func(s *errorServer)
		want   string
	}{
		{"header list too large", 1, func(s *errorServer) {
			b := block(":status", "200", "a", big, "b", big)
			s.raw(FrameHeaders, 0, 1, b[:16384]...)
			for b = b[16384:]; len(b) > 16384; b = b[16384:] {
				s.raw(FrameContinuation, 0, 1, b[:16384]...)
			}
			s.raw(FrameContinuation, FlagContinuationEndHeaders, 1, b...)
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"invalid field before CONTINUATION", 1, func(s *errorServer) {
			s.raw(FrameHeaders, 0, 1, block(":status", "200", "A", "b")...)
			s.raw(FrameContinuation, FlagContinuationEndHeaders, 1, block("c", "d")...)
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"pseudo-header after a field", 1, func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block(":status", "200", "a", "b", ":foo", "c")...)
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"name", 1, func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block(":status", "200", "a(b", "c")...)
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"value 0x0b", 1, func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block(":status", "200", "a", "b\x0b")...)
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"value 0x7f", 1, func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block(":status", "200", "a", "b\x7f")...)
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"PUSH_PROMISE with an invalid field", 1, func(s *errorServer) {
			s.raw(FramePushPromise, FlagPushPromiseEndHeaders, 1, append(u32(2), block(":method", "GET", "A", "b")...)...)
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"two :status", 1, func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block(":status", "200", ":status", "200")...)
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"no :status", 1, func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block("a", "b")...)
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"invalid field on a stream not open", 5, func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 5, block(":status", "200", "A", "b")...)
		}, "RST_STREAM 5 PROTOCOL_ERROR"},
		{"third header block", 1, func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, status200...)
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block("a", "b")...)
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block("c", "d")...)
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"DATA after trailers", 1, func(s *errorServer) {
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, status200...)
			s.raw(FrameHeaders, FlagHeadersEndHeaders, 1, block("a", "b")...)
			s.raw(FrameData, 0, 1, 'x')
		}, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"DATA before HEADERS", 1, func(s *errorServer) { s.raw(FrameData, 0, 1, 'x') }, "RST_STREAM 1 PROTOCOL_ERROR"},
		{"stream WINDOW_UPDATE 0", 1, func(s *errorServer) { s.raw(FrameWindowUpdate, 0, 1, 0, 0, 0, 0) }, "RST_STREAM 1 FLOW_CONTROL_ERROR"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newErrorServer(t, &Transport{})
				done := s.request(true)
				tt.send(s)
				synctest.Wait()
				if got := s.frames(); !slices.Contains(got, tt.want) || slices.ContainsFunc(got, func(f string) bool { return strings.HasPrefix(f, "GOAWAY") }) {
					t.Errorf("frames %q, want %q without GOAWAY", got, tt.want)
				}
				if s.cc.State().Closed {
					t.Error("connection closed")
				}
				if tt.stream == 1 {
					if err := <-done; err == nil {
						t.Error("request answered")
					}
				}
			})
		})
	}
}

// A PING lost closes the connection with GOAWAY PROTOCOL_ERROR "Failed
// ping.".
func TestChromiumLostPing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newErrorServer(t, &Transport{PrefacePing: 10 * time.Second})
		time.Sleep(11 * time.Second)
		s.request(true) // with a PING
		time.Sleep(11 * time.Second)
		synctest.Wait()
		got := s.frames()
		if want := `GOAWAY PROTOCOL_ERROR "Failed ping."`; len(got) == 0 || got[len(got)-1] != want {
			t.Errorf("frames %q, want last %q", got, want)
		}
	})
}

// Without ChromiumErrors, Go's errors are kept: GOAWAY without debug data
// for a first frame other than SETTINGS.
func TestNoChromiumErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := net.Pipe()
		go io.Copy(io.Discard, server)
		go NewFramer(server, server).WritePing(false, [8]byte{})
		cc, err := (&Transport{Settings: chromeSettings}).newClientConn(client, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if !cc.State().Closed {
			t.Error("connection open after a PING before SETTINGS")
		}
	})
}

// MAX_FRAME_SIZE out of range is ignored: the DATA frames of a request
// body keep their size.
func TestChromiumMaxFrameSizeIgnored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newErrorServer(t, &Transport{})
		s.fr.WriteSettings(Setting{SettingMaxFrameSize, 1})
		synctest.Wait()
		req, _ := http.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("hello"))
		go s.cc.RoundTrip(req)
		synctest.Wait()
		if got := s.frames(); !slices.Contains(got, "DATA 1 5") {
			t.Errorf("frames %q, want DATA 1 5", got)
		}
	})
}

// A first frame other than SETTINGS is taken, and NO_RFC7540_PRIORITIES 1
// in the first SETTINGS may come again.
func TestChromiumFirstSettings(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newErrorServerStart(t, &Transport{}, func(fr *Framer) {
			fr.WritePing(false, [8]byte{1})
			fr.WriteSettings(Setting{SettingNoRFC7540Priorities, 1})
		})
		s.fr.WriteSettings(Setting{SettingNoRFC7540Priorities, 1})
		done := s.request(true)
		s.raw(FrameHeaders, FlagHeadersEndHeaders|FlagHeadersEndStream, 1, status200...)
		synctest.Wait()
		if err := <-done; err != nil {
			t.Errorf("request: %v", err)
		}
		if s.cc.State().Closed {
			t.Error("connection closed")
		}
	})
}

// A PING ACK acknowledges the PING in flight whatever its payload, as in
// Chromium: the connection is not lost.
func TestChromiumPingAckPayload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newErrorServer(t, &Transport{PrefacePing: 10 * time.Second})
		time.Sleep(11 * time.Second)
		s.request(true) // with PING 1
		s.raw(FramePing, FlagPingAck, 0, make([]byte, 8)...)
		time.Sleep(11 * time.Second)
		synctest.Wait()
		if s.cc.State().Closed {
			t.Errorf("connection closed: %q", s.frames())
		}
	})
}
