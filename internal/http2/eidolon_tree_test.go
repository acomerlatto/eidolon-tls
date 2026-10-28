// PRIORITY frames, fixed HEADERS priority and first stream (patch 0026).

package http2

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

// firefoxTree is the priority tree of Firefox up to version 88: six idle
// streams, the requests from stream 15 depending on stream 13.
var firefoxTree = []PriorityFrameParam{
	{3, PriorityParam{StreamDep: 0, Weight: 200}},
	{5, PriorityParam{StreamDep: 0, Weight: 100}},
	{7, PriorityParam{StreamDep: 0, Weight: 0}},
	{9, PriorityParam{StreamDep: 7, Weight: 0}},
	{11, PriorityParam{StreamDep: 3, Weight: 0}},
	{13, PriorityParam{StreamDep: 0, Weight: 240}},
}

// The PRIORITY frames follow SETTINGS and the connection WINDOW_UPDATE in
// order, and the requests start at FirstStreamID with HeaderPriority.
func TestPriorityTree(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := net.Pipe()
		seen := wireServer(server, wireOptions{})
		header := PriorityParam{StreamDep: 13, Weight: 41}
		tr := &Transport{
			Settings:         []Setting{{ID: SettingInitialWindowSize, Val: 131072}},
			ConnWindowUpdate: 12517377,
			PriorityFrames:   firefoxTree,
			HeaderPriority:   &header,
			FirstStreamID:    15,
		}
		cc, err := tr.newClientConn(client, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		synctest.Wait()
		client.Close()
		var got []string
		for f := range seen {
			switch f.typ {
			case FrameSettings:
				if f.flags&FlagSettingsAck == 0 {
					got = append(got, "SETTINGS")
				}
			case FrameWindowUpdate:
				got = append(got, fmt.Sprint("WINDOW_UPDATE ", f.incr))
			case FramePriority, FrameHeaders:
				got = append(got, fmt.Sprintf("%v %d %+v", f.typ, f.stream, f.prio))
			}
		}
		want := []string{"SETTINGS", "WINDOW_UPDATE 12517377"}
		for _, p := range firefoxTree {
			want = append(want, fmt.Sprintf("PRIORITY %d %+v", p.StreamID, p.PriorityParam))
		}
		want = append(want, fmt.Sprintf("HEADERS 15 %+v", header), fmt.Sprintf("HEADERS 17 %+v", header))
		if !slices.Equal(got, want) {
			t.Errorf("frames\n%q\nwant\n%q", got, want)
		}
	})
}

// With another first stream, a single-use connection still takes its
// first request and only it, and a connection closed before any request
// takes one, which then fails with the error of the connection.
func TestFirstStreamIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := net.Pipe()
		wireServer(server, wireOptions{})
		cc, err := (&Transport{FirstStreamID: 15}).newClientConn(client, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !cc.idleState().canTakeNewRequest {
			t.Fatal("new single-use connection takes no request")
		}
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if cc.idleState().canTakeNewRequest {
			t.Error("used single-use connection takes another request")
		}
		client.Close()

		client, server = net.Pipe()
		go io.Copy(io.Discard, server)
		cc, err = (&Transport{FirstStreamID: 15}).newClientConn(client, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		server.Close()
		time.Sleep(time.Second)
		synctest.Wait()
		if !cc.State().Closed {
			t.Fatal("connection open")
		}
		if !cc.idleState().canTakeNewRequest {
			t.Error("connection closed before any request takes none")
		}
	})
}

func TestCheckPriorities(t *testing.T) {
	for _, tt := range []struct {
		frames []PriorityFrameParam
		header *PriorityParam
		first  uint32
		ok     bool
	}{
		{firefoxTree, &PriorityParam{StreamDep: 13, Weight: 41}, 15, true},
		{nil, nil, 0, true},
		{nil, nil, 1, true},
		{[]PriorityFrameParam{{StreamID: 0, PriorityParam: PriorityParam{StreamDep: 3}}}, nil, 0, false},
		{[]PriorityFrameParam{{StreamID: 1 << 31}}, nil, 0, false},
		{[]PriorityFrameParam{{StreamID: 3, PriorityParam: PriorityParam{StreamDep: 1 << 31}}}, nil, 0, false},
		{[]PriorityFrameParam{{StreamID: 3, PriorityParam: PriorityParam{StreamDep: 3}}}, nil, 0, false},
		{nil, &PriorityParam{StreamDep: 1 << 31}, 0, false},
		{nil, nil, 2, false},
		{nil, nil, 1 << 31, false},
		{nil, nil, 1<<31 - 1, true},
	} {
		if err := CheckPriorities(tt.frames, tt.header, tt.first); (err == nil) != tt.ok {
			t.Errorf("CheckPriorities(%v, %v, %d) = %v, want ok %v", tt.frames, tt.header, tt.first, err, tt.ok)
		}
	}
}
