// WINDOW_UPDATE of Chromium (patch 0024).

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

// windowUpdates reads a response of 4 MiB in reads of 16 KiB with read
// between them, over a connection with the windows of Chrome, a stream of
// 6 MiB and a connection of 15 MiB, and returns the WINDOW_UPDATE frames
// sent after the first, as "stream:increment". It runs in a synctest
// bubble.
func windowUpdates(t *testing.T, chromium bool, read func(i int, r io.Reader)) []string {
	client, server := net.Pipe()
	seen := wireServer(server, wireOptions{body: make([]byte, 4<<20)})
	tr := &Transport{
		Settings:             []Setting{{ID: SettingInitialWindowSize, Val: 6291456}},
		ConnWindowUpdate:     15663105,
		ChromiumWindowUpdate: chromium,
	}
	cc, err := tr.newClientConn(client, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	synctest.Wait() // the whole body is buffered
	buf := make([]byte, 16384)
	for i := 0; ; i++ {
		read(i, resp.Body)
		if _, err := io.ReadFull(resp.Body, buf); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // the updates are on the wire, in order
	}
	resp.Body.Close()
	client.Close()
	var got []string
	for f := range seen {
		if f.typ == FrameWindowUpdate {
			got = append(got, fmt.Sprintf("%d:%d", f.stream, f.incr))
		}
	}
	return got[1:]
}

// The stream window goes back once more than half of it, 3 MiB, has been
// read; the connection window, of which less than half is read, once 5 s
// have passed, with the stream window read since its update; the end of
// the stream sends none.
func TestChromiumWindowUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		got := windowUpdates(t, true, func(i int, _ io.Reader) {
			if i == 193 { // before the 194th read
				time.Sleep(6 * time.Second)
			}
		})
		want := []string{
			"1:3162112", // 193 reads: 3162112 > 3145728
			"0:3178496", // 6 s later, the 194 reads on the connection
			"1:16384",   // and the one read since on the stream
		}
		if !slices.Equal(got, want) {
			t.Errorf("WINDOW_UPDATE %v, want %v", got, want)
		}
	})
}

// Without ChromiumWindowUpdate, each read of 16 KiB gives its window back.
func TestNoChromiumWindowUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		got := windowUpdates(t, false, func(int, io.Reader) {})
		if len(got) < 256 || got[0] != "0:16384" || got[1] != "1:16384" {
			t.Errorf("WINDOW_UPDATE %d frames, starting %v", len(got), got[:min(len(got), 2)])
		}
	})
}

// The 5 s count when bytes are read, not when a DATA frame arrives: a
// response after a pause brings no update until its body is read, and
// then one with all that was read on the connection; a connection window
// of 65535 goes back once more than half, 32767, is read, counting the
// window of a body closed unread.
func TestChromiumWindowUpdateOnRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := net.Pipe()
		seen := wireServer(server, wireOptions{body: make([]byte, 16384)})
		cc, err := (&Transport{Settings: []Setting{}, ChromiumWindowUpdate: true}).newClientConn(client, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		step := func(name string) {
			synctest.Wait()
			for {
				select {
				case f := <-seen:
					if f.typ == FrameWindowUpdate {
						got = append(got, fmt.Sprintf("%d:%d", f.stream, f.incr))
					}
					continue
				default:
				}
				break
			}
			got = append(got, name)
		}
		get := func(read int) {
			req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			step("arrived")
			io.ReadFull(resp.Body, make([]byte, read))
			step("read")
			resp.Body.Close()
		}
		get(16384)
		time.Sleep(5 * time.Second) // exactly: 5 s is enough
		get(8192)                   // closed with 8192 unread
		get(16384)
		get(16384)
		want := []string{
			"arrived", "read",
			"arrived", "0:24576", "read",
			"arrived", "read", // 8192 + 16384 unsent
			"arrived", "0:40960", "read",
		}
		if !slices.Equal(got, want) {
			t.Errorf("%v, want %v", got, want)
		}
		client.Close()
	})
}
