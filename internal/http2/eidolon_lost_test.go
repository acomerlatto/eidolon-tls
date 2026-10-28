// A lost connection ends its streams with the read error (patch 0018).

package http2

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// failReadConn returns io.EOF from Read once fail is closed, while writes
// still go through.
type failReadConn struct {
	net.Conn
	reads chan []byte
	fail  chan struct{}
}

func newFailReadConn(c net.Conn) *failReadConn {
	f := &failReadConn{Conn: c, reads: make(chan []byte), fail: make(chan struct{})}
	go func() {
		for {
			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			if err != nil {
				close(f.reads)
				return
			}
			select {
			case f.reads <- buf[:n]:
			case <-f.fail:
				return
			}
		}
	}()
	return f
}

func (f *failReadConn) Read(p []byte) (int, error) {
	select {
	case b, ok := <-f.reads:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, b), nil // the frames used here fit in p
	case <-f.fail:
		return 0, io.EOF
	}
}

// markDeadHook runs hook when a connection is marked dead.
type markDeadHook struct {
	ClientConnPool
	hook func(*ClientConn)
}

func (p markDeadHook) MarkDead(cc *ClientConn) { p.hook(cc) }

// gatedBody returns "a", then closes waiting and waits for open before
// returning "b" and EOF.
type gatedBody struct {
	waiting, open chan struct{}
	n             int
}

func (b *gatedBody) Read(p []byte) (int, error) {
	b.n++
	switch b.n {
	case 1:
		return copy(p, "a"), nil
	case 2:
		close(b.waiting)
		<-b.open
		return copy(p, "b"), nil
	}
	return 0, io.EOF
}

// A reused connection lost while a request body is being sent ends the
// request with the read error, the sign of a lost connection, even when
// the body writer looks at the connection while the read loop marks it
// dead: the read loop releases its lock there, and the writer used to end
// the stream first with errClientConnClosed.
func TestLostConnReadErrorWins(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		io.ReadFull(server, make([]byte, len(ClientPreface)))
		fr := NewFramer(server, server)
		go fr.WriteSettings()
		for {
			if _, err := fr.ReadFrame(); err != nil {
				return
			}
		}
	}()
	conn := newFailReadConn(client)
	body := &gatedBody{waiting: make(chan struct{}), open: make(chan struct{})}
	var aborted atomic.Bool
	tr := &Transport{}
	tr.ConnPool = markDeadHook{ClientConnPool: &clientConnPool{t: tr}, hook: func(cc *ClientConn) {
		// The body writer runs now, then the stream must be ended.
		close(body.open)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			cc.mu.Lock()
			cs := cc.streams[1]
			done := cs == nil
			if cs != nil {
				select {
				case <-cs.abort:
					done = true
				default:
				}
			}
			cc.mu.Unlock()
			if done {
				aborted.Store(true)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}}
	cc, err := tr.newClientConn(conn, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	atomic.StoreUint32(&cc.atomicReused, 1)
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/", body)
	req.ContentLength = -1
	errc := make(chan error, 1)
	go func() {
		_, err := cc.RoundTrip(req)
		errc <- err
	}()
	// The first byte of the body is sent; the writer waits for the rest.
	select {
	case <-body.waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("body not read")
	}
	close(conn.fail)
	select {
	case err := <-errc:
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("RoundTrip error %v, want %v", err, io.ErrUnexpectedEOF)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RoundTrip did not return")
	}
	if !aborted.Load() {
		t.Fatal("stream not ended while the connection was marked dead")
	}
}
