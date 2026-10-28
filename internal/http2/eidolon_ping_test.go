// Preface PING of Chromium (patch 0023).

package http2

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

// pingConn returns a connection with PrefacePing of 10 s to a wireServer
// with o, a function that sends a request with body (nil for a GET)
// without waiting for it, and one that closes the connection and returns
// the HEADERS, DATA with payload and PING frames the client sent, as
// "H1", "D1" and "P1" with the stream or the PING counter. It runs in a
// synctest bubble.
func pingConn(t *testing.T, o wireOptions) (*ClientConn, func(body io.Reader) <-chan error, func() []string) {
	client, server := net.Pipe()
	seen := wireServer(server, o)
	cc, err := (&Transport{PrefacePing: 10 * time.Second}).newClientConn(client, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	send := func(body io.Reader) <-chan error {
		method := http.MethodGet
		if body != nil {
			method = http.MethodPost
		}
		req, _ := http.NewRequest(method, "https://example.com/", body)
		done := make(chan error, 1)
		go func() {
			resp, err := cc.RoundTrip(req)
			if err == nil {
				resp.Body.Close()
			}
			done <- err
		}()
		synctest.Wait()
		return done
	}
	frames := func() []string {
		client.Close()
		var got []string
		for f := range seen {
			switch {
			case f.typ == FrameHeaders:
				got = append(got, fmt.Sprint("H", f.stream))
			case f.typ == FrameData && f.length > 0:
				got = append(got, fmt.Sprint("D", f.stream))
			case f.typ == FramePing && f.flags&FlagPingAck == 0:
				got = append(got, fmt.Sprint("P", binary.BigEndian.Uint64(f.ping[:])))
			}
		}
		return got
	}
	return cc, send, frames
}

// No PING on a connection read from in the last 10 s, new or not; after
// 10 s without a read, a PING right after the next HEADERS, or after the
// next DATA with payload, counting from 1; never after an empty DATA.
func TestPrefacePing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, send, frames := pingConn(t, wireOptions{})
		<-send(nil) // new connection
		<-send(nil)
		time.Sleep(11 * time.Second)
		<-send(nil)
		<-send(nil) // a response was just read
		time.Sleep(11 * time.Second)
		<-send(nil)
		// The HEADERS go right after a read, the DATA 11 s later.
		pr, pw := io.Pipe()
		done := send(pr)
		time.Sleep(11 * time.Second)
		pw.Write([]byte("body"))
		pw.Close()
		<-done
		// An empty DATA, only ending the stream, sends none.
		pr, pw = io.Pipe()
		done = send(pr)
		time.Sleep(11 * time.Second)
		pw.Close()
		<-done
		want := []string{"H1", "H3", "H5", "P1", "H7", "H9", "P2", "H11", "D11", "P3", "H13"}
		if got := frames(); !slices.Equal(got, want) {
			t.Errorf("frames %v, want %v", got, want)
		}
	})
}

// Without a read for 10 s while the PING is unanswered, the connection is
// lost; meanwhile, no other PING is sent.
func TestPrefacePingLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cc, send, frames := pingConn(t, wireOptions{silent: true})
		time.Sleep(11 * time.Second)
		first := send(nil) // t=11: PING
		time.Sleep(4 * time.Second)
		second := send(nil) // t=15: no PING, one is being checked
		time.Sleep(5900 * time.Millisecond)
		synctest.Wait()
		if cc.State().Closed {
			t.Fatal("closed at 20.9 s")
		}
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if !cc.State().Closed {
			t.Fatal("open at 21.1 s")
		}
		for _, done := range []<-chan error{first, second} {
			if err := <-done; err == nil {
				t.Error("request answered on a lost connection")
			}
		}
		if got, want := frames(), []string{"H1", "P1", "H3"}; !slices.Equal(got, want) {
			t.Errorf("frames %v, want %v", got, want)
		}
	})
}

// An unanswered PING is checked again while the connection reads: it is
// lost 10 s after the last read, not 10 s after the PING.
func TestPrefacePingRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cc, send, frames := pingConn(t, wireOptions{noPings: true})
		time.Sleep(11 * time.Second)
		<-send(nil) // t=11: PING, response read
		time.Sleep(4 * time.Second)
		<-send(nil) // t=15: response read
		time.Sleep(9900 * time.Millisecond)
		synctest.Wait()
		if cc.State().Closed {
			t.Fatal("closed at 24.9 s")
		}
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if !cc.State().Closed {
			t.Fatal("open at 25.1 s")
		}
		if got, want := frames(), []string{"H1", "P1", "H3"}; !slices.Equal(got, want) {
			t.Errorf("frames %v, want %v", got, want)
		}
	})
}

// Without PrefacePing, no PING however long the connection was not read.
func TestNoPrefacePing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := net.Pipe()
		seen := wireServer(server, wireOptions{})
		cc, err := (&Transport{}).newClientConn(client, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		client.Close()
		for f := range seen {
			if f.typ == FramePing {
				t.Error("PING sent")
			}
		}
	})
}
