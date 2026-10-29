package http2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"testing/synctest"
)

// alpsTestConn is a connection whose server sent data as ALPS.
type alpsTestConn struct {
	net.Conn
	data []byte
}

func (c alpsTestConn) PeerApplicationSettings() []byte { return c.data }

// alpsFrame is a frame in ALPS data.
func alpsFrame(t FrameType, flags Flags, stream uint32, payload ...byte) []byte {
	var b bytes.Buffer
	NewFramer(&b, nil).WriteRawFrame(t, flags, stream, payload)
	return b.Bytes()
}

// alpsSettings is a SETTINGS frame in ALPS data.
func alpsSettings(settings ...Setting) []byte {
	var p []byte
	for _, s := range settings {
		p = binary.BigEndian.AppendUint16(p, uint16(s.ID))
		p = binary.BigEndian.AppendUint32(p, s.Val)
	}
	return alpsFrame(FrameSettings, 0, 0, p...)
}

// The ALPS of the server is decoded as Chromium's AlpsDecoder: the
// settings by order of ID, the last value of an ID winning, and the errors
// by the precedence of Decode.
func TestDecodeALPS(t *testing.T) {
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	ping := alpsFrame(FramePing, 0, 0, make([]byte, 8)...)
	ack := alpsFrame(FrameSettings, FlagSettingsAck, 0)
	acceptCH := alpsFrame(frameAcceptCH, 0, 0, 0, 1, 'o', 0, 1, 'v')
	for _, tt := range []struct {
		name string
		data []byte
		want []Setting
		err  int
	}{
		{"empty", nil, nil, 0},
		{"settings", cat(alpsSettings(Setting{SettingMaxConcurrentStreams, 10}, Setting{SettingHeaderTableSize, 0}),
			alpsSettings(Setting{SettingMaxConcurrentStreams, 20})),
			[]Setting{{SettingHeaderTableSize, 0}, {SettingMaxConcurrentStreams, 20}}, 0},
		{"empty SETTINGS", alpsSettings(), nil, 0},
		{"unknown frame on a stream", alpsFrame(0xfa, 0xff, 3, 1, 2), nil, 0},
		{"ACCEPT_CH", cat(acceptCH, alpsSettings(Setting{SettingEnablePush, 0})), []Setting{{SettingEnablePush, 0}}, 0},
		{"malformed ACCEPT_CH", alpsFrame(frameAcceptCH, 0, 0, 0, 9), nil, 0},
		{"ALTSVC", alpsFrame(0xa, 0, 0, 0, 0), nil, 0},

		{"SETTINGS on a stream", alpsFrame(FrameSettings, 0, 1), nil, alpsFramingError},
		{"SETTINGS of 5 bytes", alpsFrame(FrameSettings, 0, 0, 0, 3, 0, 0, 0), nil, alpsFramingError},
		{"SETTINGS ACK with payload", alpsFrame(FrameSettings, FlagSettingsAck, 0, make([]byte, 6)...), nil, alpsFramingError},
		{"PING of 7 bytes", alpsFrame(FramePing, 0, 0, make([]byte, 7)...), nil, alpsFramingError},
		{"oversized", alpsFrame(0xfa, 0, 0, make([]byte, 16385)...), nil, alpsFramingError},
		{"CONTINUATION alone", alpsFrame(FrameContinuation, FlagContinuationEndHeaders, 1), nil, alpsFramingError},
		{"PRIORITY_UPDATE on stream 0", alpsFrame(FramePriorityUpdate, 0, 0, u32(0)...), nil, alpsFramingError},
		{"forbidden, then framing", cat(ping, alpsFrame(FrameSettings, 0, 1)), nil, alpsFramingError},
		{"framing in a truncated frame", alpsFrame(FrameSettings, 0, 1, make([]byte, 6)...)[:12], nil, alpsFramingError},

		{"PING", ping, nil, alpsForbiddenFrame},
		{"DATA", alpsFrame(FrameData, 0, 1, 'x'), nil, alpsForbiddenFrame},
		{"HEADERS", alpsFrame(FrameHeaders, FlagHeadersEndHeaders, 1, 0x88), nil, alpsForbiddenFrame},
		{"PRIORITY", alpsFrame(FramePriority, 0, 1, 0, 0, 0, 0, 0), nil, alpsForbiddenFrame},
		{"RST_STREAM", alpsFrame(FrameRSTStream, 0, 1, u32(0)...), nil, alpsForbiddenFrame},
		{"PUSH_PROMISE", alpsFrame(FramePushPromise, FlagPushPromiseEndHeaders, 1, u32(2)...), nil, alpsForbiddenFrame},
		{"GOAWAY", alpsFrame(FrameGoAway, 0, 0, make([]byte, 8)...), nil, alpsForbiddenFrame},
		{"WINDOW_UPDATE of 0", alpsFrame(FrameWindowUpdate, 0, 0, u32(0)...), nil, alpsForbiddenFrame},
		{"HEADERS, CONTINUATION", cat(alpsFrame(FrameHeaders, 0, 1, 0x88), alpsFrame(FrameContinuation, FlagContinuationEndHeaders, 1)), nil, alpsForbiddenFrame},
		{"forbidden, then ACK", cat(ping, ack), nil, alpsForbiddenFrame},
		{"forbidden, then truncated", cat(ping, alpsSettings(Setting{1, 1})[:10]), nil, alpsForbiddenFrame},
		{"forbidden header, truncated", ping[:12], nil, alpsForbiddenFrame},
		{"forbidden, then ACCEPT_CH on a stream", cat(ping, alpsFrame(frameAcceptCH, 0, 1)), nil, alpsForbiddenFrame},

		{"SETTINGS ACK", ack, nil, alpsSettingsWithAck},
		{"ACK, then truncated", cat(ack, ping[:5]), nil, alpsSettingsWithAck},
		{"ACK, then SETTINGS", cat(ack, alpsSettings(Setting{1, 1})), nil, alpsSettingsWithAck},

		{"truncated header", ping[:5], nil, alpsNotOnFrameBoundary},
		{"truncated payload", alpsSettings(Setting{1, 1})[:12], nil, alpsNotOnFrameBoundary},
		{"truncated, ACCEPT_CH on a stream", cat(alpsFrame(frameAcceptCH, 0, 1), ping[:5]), nil, alpsNotOnFrameBoundary},

		{"ACCEPT_CH on a stream", alpsFrame(frameAcceptCH, 0, 1), nil, alpsAcceptChInvalidStream},
		{"ACCEPT_CH with flags", alpsFrame(frameAcceptCH, 1, 0), nil, alpsAcceptChWithFlags},
		{"first ACCEPT_CH error", cat(alpsFrame(frameAcceptCH, 0, 1), alpsFrame(frameAcceptCH, 1, 0)), nil, alpsAcceptChInvalidStream},
		{"ACCEPT_CH with flags first", cat(alpsFrame(frameAcceptCH, 1, 0), alpsFrame(frameAcceptCH, 0, 1)), nil, alpsAcceptChWithFlags},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, n := decodeALPS(tt.data)
			if n != tt.err || !slices.Equal(got, tt.want) {
				t.Errorf("decodeALPS = %v, %d; want %v, %d", got, n, tt.want, tt.err)
			}
		})
	}
}

// alpsClient starts a connection with tr whose server sent data as ALPS,
// in a synctest bubble, and returns it with the error of
// newClientConn and the frames the client sent. The server answers
// nothing.
func alpsClient(t *testing.T, tr *Transport, data []byte) (*ClientConn, error, func() []string) {
	t.Helper()
	client, server := net.Pipe()
	seen := make(chan string, 64)
	go func() {
		defer close(seen)
		defer server.Close()
		if _, err := io.ReadFull(server, make([]byte, len(ClientPreface))); err != nil {
			return
		}
		fr := NewFramer(server, server)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			seen <- summarize(f)
		}
	}()
	tr.Settings, tr.ConnWindowUpdate = chromeSettings, 15663105
	cc, err := tr.newClientConn(alpsTestConn{client, data}, false, nil)
	if cc != nil {
		t.Cleanup(func() { cc.Close() })
	}
	return cc, err, func() []string {
		synctest.Wait()
		var got []string
		for {
			select {
			case f, ok := <-seen:
				if ok {
					got = append(got, f)
					continue
				}
			default:
			}
			return got
		}
	}
}

// With ChromiumALPS, the SETTINGS of the ALPS apply before the first frame
// of the server, without ACK; a MAX_CONCURRENT_STREAMS there survives a
// first SETTINGS frame without one, which with the errors of Go raises the
// limit to Go's default.
func TestChromiumALPSSettings(t *testing.T) {
	for _, chromium := range []bool{true, false} {
		t.Run(fmt.Sprint("ChromiumErrors=", chromium), func(t *testing.T) {
			testChromiumALPSSettings(t, chromium)
		})
	}
}

func testChromiumALPSSettings(t *testing.T, chromiumErrors bool) {
	synctest.Test(t, func(t *testing.T) {
		tr := &Transport{ChromiumALPS: true, ChromiumHPACK: true, ChromiumErrors: chromiumErrors}
		cc, err, frames := alpsClient(t, tr, alpsSettings(
			Setting{SettingMaxConcurrentStreams, 7}, Setting{SettingHeaderTableSize, 100}, Setting{SettingInitialWindowSize, 1000}))
		if err != nil {
			t.Fatal(err)
		}
		if got := frames(); !slices.Equal(got, []string{"SETTINGS", "WINDOW_UPDATE 0 15663105"}) {
			t.Errorf("client sent %q, without SETTINGS ACK", got)
		}
		cc.mu.Lock()
		if cc.maxConcurrentStreams != 7 || cc.peerMaxHeaderTableSize != 100 || cc.flow.initial != 1000 {
			t.Errorf("max streams %d, table %d, window %d", cc.maxConcurrentStreams, cc.peerMaxHeaderTableSize, cc.flow.initial)
		}
		cc.mu.Unlock()
		rl := &clientConnReadLoop{cc: cc}
		if err := rl.processSettingsNoWrite(&SettingsFrame{FrameHeader: FrameHeader{valid: true, Type: FrameSettings}}); err != nil {
			t.Fatal(err)
		}
		if cc.maxConcurrentStreams != 7 {
			t.Errorf("max streams %d after the first SETTINGS, want 7", cc.maxConcurrentStreams)
		}
	})
}

// Without ChromiumALPS, or without ALPS data, nothing applies, and the
// first SETTINGS frame raises the limit of streams as in Go, with its
// errors.
func TestNoChromiumALPS(t *testing.T) {
	for _, tt := range []struct {
		name string
		tr   *Transport
		data []byte
	}{
		{"off", &Transport{}, alpsSettings(Setting{SettingMaxConcurrentStreams, 7})},
		{"no ALPS", &Transport{ChromiumALPS: true}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cc, err, _ := alpsClient(t, tt.tr, tt.data)
				if err != nil {
					t.Fatal(err)
				}
				if cc.maxConcurrentStreams != initialMaxConcurrentStreams {
					t.Errorf("max streams %d", cc.maxConcurrentStreams)
				}
				rl := &clientConnReadLoop{cc: cc}
				rl.processSettingsNoWrite(&SettingsFrame{FrameHeader: FrameHeader{valid: true, Type: FrameSettings}})
				if cc.maxConcurrentStreams != defaultMaxConcurrentStreams {
					t.Errorf("max streams %d after the first SETTINGS", cc.maxConcurrentStreams)
				}
			})
		})
	}
}

// Malformed ALPS, or a setting Chromium refuses, closes the connection
// with the GOAWAY of Chromium after the preface, and fails newClientConn
// with it.
func TestChromiumALPSErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
		want string
	}{
		{"forbidden", alpsFrame(FramePing, 0, 0, make([]byte, 8)...), `GOAWAY PROTOCOL_ERROR "Error parsing ALPS: 2"`},
		{"truncated", alpsSettings(Setting{1, 1})[:10], `GOAWAY PROTOCOL_ERROR "Error parsing ALPS: 3"`},
		{"setting", alpsSettings(Setting{SettingEnableConnectProtocol, 2}, Setting{SettingNoRFC7540Priorities, 0}),
			`GOAWAY PROTOCOL_ERROR "Invalid value for spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL."`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cc, err, frames := alpsClient(t, &Transport{ChromiumALPS: true, ChromiumErrors: true}, tt.data)
				var ce chromiumError
				if cc != nil || !errors.As(err, &ce) || ce.Code != ErrCodeProtocol {
					t.Fatalf("newClientConn = %v, %v", cc, err)
				}
				want := []string{"SETTINGS", "WINDOW_UPDATE 0 15663105", tt.want}
				if got := frames(); !slices.Equal(got, want) {
					t.Errorf("client sent %q, want %q", got, want)
				}
			})
		})
	}
}

// Without ChromiumErrors, a setting Go refuses closes the connection with
// GOAWAY PROTOCOL_ERROR and the error of Go as debug data.
func TestChromiumALPSGoSetting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := &Transport{ChromiumALPS: true}
		client, server := net.Pipe()
		go func() {
			io.Copy(io.Discard, server)
			server.Close()
		}()
		tr.Settings = chromeSettings
		_, err := tr.newClientConn(alpsTestConn{client, alpsSettings(Setting{SettingEnablePush, 2})}, false, nil)
		var ce chromiumError
		if !errors.As(err, &ce) || ce.Code != ErrCodeProtocol || ce.Debug != ConnectionError(ErrCodeProtocol).Error() {
			t.Errorf("newClientConn: %v", err)
		}
	})
}

// RefuseConn refuses the connection before the ALPS: the GOAWAY is that of
// the refusal, even with malformed ALPS.
func TestRefuseConnALPS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := net.Pipe()
		seen := make(chan string, 8)
		go func() {
			defer close(seen)
			io.ReadFull(server, make([]byte, len(ClientPreface)))
			fr := NewFramer(server, server)
			for {
				f, err := fr.ReadFrame()
				if err != nil {
					return
				}
				seen <- summarize(f)
			}
		}()
		tr := &Transport{ChromiumALPS: true, Settings: chromeSettings, ConnWindowUpdate: 15663105}
		tr.RefuseConn(alpsTestConn{client, alpsFrame(FramePing, 0, 0, make([]byte, 8)...)}, ErrCodeInadequateSecurity)
		server.Close()
		var got []string
		for f := range seen {
			got = append(got, f)
		}
		if want := []string{"SETTINGS", "WINDOW_UPDATE 0 15663105", `GOAWAY INADEQUATE_SECURITY ""`}; !slices.Equal(got, want) {
			t.Errorf("client sent %q, want %q", got, want)
		}
	})
}
