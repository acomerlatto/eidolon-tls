package dispatch_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// limitLab returns a lab server of HTTP/1.1 for a.test, b.test and c.test,
// whose /block requests wait for release, each telling arrived first, and
// a transport to it with MaxConns.
func limitLab(t *testing.T, maxConns int) (*lab.Server, *dispatch.Transport, chan struct{}, chan struct{}) {
	return limitLabPlain(t, maxConns, false)
}

// limitLabPlain is limitLab, without TLS when plain.
func limitLabPlain(t *testing.T, maxConns int, plain bool) (*lab.Server, *dispatch.Transport, chan struct{}, chan struct{}) {
	t.Helper()
	return limitLabProtos(t, maxConns, plain, []string{"http/1.1"})
}

// limitLabProtos is limitLabPlain with the protocols the server offers.
func limitLabProtos(t *testing.T, maxConns int, plain bool, protos []string) (*lab.Server, *dispatch.Transport, chan struct{}, chan struct{}) {
	t.Helper()
	cert, err := lab.NewCertificate(time.Hour, "a.test", "b.test", "c.test")
	if err != nil {
		t.Fatal(err)
	}
	arrived, release := make(chan struct{}, 4), make(chan struct{})
	srv := lab.Start(t, lab.Options{Certificate: &cert, Plain: plain, NextProtos: protos, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/block" {
			arrived <- struct{}{}
			<-release
		}
		io.WriteString(w, "ok")
	})})
	tr := transport(srv)
	tr.MaxConns = maxConns
	t.Cleanup(func() { tr.Close() })
	return srv, tr, arrived, release
}

// isClosed reports whether the client closed c within a short time.
func isClosed(c *lab.Conn) bool {
	select {
	case <-c.Done():
		return true
	case <-time.After(200 * time.Millisecond):
		return false
	}
}

// Over MaxConns, a new connection first closes the idle connection used
// least recently of the first host that has one.
func TestMaxConnsClosesIdle(t *testing.T) {
	srv, tr, _, _ := limitLab(t, 2)
	for _, host := range []string{"a.test", "b.test", "c.test", "a.test"} {
		if _, err := send(context.Background(), tr, http.MethodGet, "https://"+host+"/", nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := srv.Accepted(); n != 4 {
		t.Fatalf("%d connections, want 4", n)
	}
	// c.test closed the one of a.test, then a.test the one of b.test.
	a, b, c := srv.NextConn(t), srv.NextConn(t), srv.NextConn(t)
	if !isClosed(a) || !isClosed(b) || isClosed(c) {
		t.Error("want the connections of a.test and b.test closed, the one of c.test open")
	}
}

// Over MaxConns, without an idle HTTP/1.1 connection, a new connection
// closes the HTTP/2 connections without streams, as Chrome's
// TransportClientSocketPool asks its SpdySessions to
// (TryToCloseSocketsInLayeredPools); one stays open while nothing waits.
func TestMaxConnsClosesIdleH2(t *testing.T) {
	srv, tr, _, _ := limitLabProtos(t, 1, false, []string{"h2"})
	if _, err := send(context.Background(), tr, http.MethodGet, "https://a.test/", nil); err != nil {
		t.Fatal(err)
	}
	a := srv.NextConn(t)
	if isClosed(a) {
		t.Fatal("the idle connection closed with nothing waiting")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := send(ctx, tr, http.MethodGet, "https://b.test/", nil); err != nil {
		t.Fatal(err)
	}
	if !isClosed(a) {
		t.Error("the idle connection of a.test is still open")
	}
}

// An HTTP/2 connection busy when a new connection starts waiting closes
// when its last stream ends, as Chrome's SpdySession when its socket pool
// is stalled (DeleteStream).
func TestMaxConnsClosesH2AfterLastStream(t *testing.T) {
	srv, tr, arrived, release := limitLabProtos(t, 1, false, []string{"h2"})
	blocked := make(chan error, 1)
	go func() {
		_, err := send(context.Background(), tr, http.MethodGet, "https://a.test/block", nil)
		blocked <- err
	}()
	<-arrived
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	waiting := make(chan error, 1)
	go func() {
		_, err := send(ctx, tr, http.MethodGet, "https://b.test/", nil)
		waiting <- err
	}()
	select {
	case err := <-waiting:
		t.Fatalf("answered over the limit: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	if err := <-waiting; err != nil {
		t.Fatal(err)
	}
	if !isClosed(srv.NextConn(t)) {
		t.Error("the connection of a.test is still open")
	}
}

// Once nothing waits for a slot, an HTTP/2 connection whose last stream
// ends stays open.
func TestMaxConnsKeepsH2AfterWait(t *testing.T) {
	srv, tr, arrived, release := limitLabProtos(t, 1, false, []string{"h2"})
	blocked := make(chan error, 1)
	go func() {
		_, err := send(context.Background(), tr, http.MethodGet, "https://a.test/block", nil)
		blocked <- err
	}()
	<-arrived
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := send(ctx, tr, http.MethodGet, "https://b.test/", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("over the limit: %v, want the deadline", err)
	}
	close(release)
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	if isClosed(srv.NextConn(t)) {
		t.Error("the connection of a.test closed with nothing waiting")
	}
}

// A dial waiting for a slot stops when its request leaves, as Chrome
// cancels a request stalled in its socket pool: the freed slot opens no
// connection nobody waits for. So does a shared dial, when its last
// request leaves.
func TestMaxConnsAbandonedDial(t *testing.T) {
	for _, tt := range []struct {
		name    string
		learned bool // b.test learned as http/1.1, which dials in its pool
	}{
		{"shared", false},
		{"pool", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, tr, arrived, release := limitLab(t, 1)
			if tt.learned {
				if _, err := send(context.Background(), tr, http.MethodGet, "https://b.test/", nil); err != nil {
					t.Fatal(err)
				}
				srv.NextConn(t) // closed for a.test
			}
			blocked := make(chan error, 1)
			go func() {
				_, err := send(context.Background(), tr, http.MethodGet, "https://a.test/block", nil)
				blocked <- err
			}()
			<-arrived
			a := srv.NextConn(t)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if _, err := send(ctx, tr, http.MethodGet, "https://b.test/", nil); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("over the limit: %v, want the deadline", err)
			}
			n := srv.Accepted()
			close(release)
			if err := <-blocked; err != nil {
				t.Fatal(err)
			}
			if isClosed(a) {
				t.Error("the connection of a.test closed with nothing waiting")
			}
			if m := srv.Accepted(); m != n {
				t.Errorf("%d connections after the wait, want %d", m, n)
			}
			if _, err := send(context.Background(), tr, http.MethodGet, "https://b.test/", nil); err != nil {
				t.Fatalf("b.test after the wait: %v", err)
			}
		})
	}
}

// A request canceled before its connection opens opens none: neither the
// shared dial of an origin not yet learned nor a dial of the HTTP/1.1
// pool.
func TestCanceledRequestDialsNothing(t *testing.T) {
	for _, learned := range []bool{false, true} {
		srv, tr, _, _ := limitLab(t, 4)
		if learned {
			if _, err := send(context.Background(), tr, http.MethodGet, "https://a.test/", nil); err != nil {
				t.Fatal(err)
			}
			tr.CloseIdleConnections()
		}
		n := srv.Accepted()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := send(ctx, tr, http.MethodGet, "https://a.test/", nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("learned %v: %v, want the cancellation", learned, err)
		}
		time.Sleep(100 * time.Millisecond)
		if m := srv.Accepted(); m != n {
			t.Errorf("learned %v: %d connections, want %d", learned, m, n)
		}
	}
}

// Without an idle connection to close, a new connection waits until its
// request ends, or a connection goes idle, which it then closes.
func TestMaxConnsWaits(t *testing.T) {
	srv, tr, arrived, release := limitLab(t, 1)
	blocked := make(chan error, 1)
	go func() {
		_, err := send(context.Background(), tr, http.MethodGet, "https://a.test/block", nil)
		blocked <- err
	}()
	<-arrived
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := send(ctx, tr, http.MethodGet, "https://b.test/", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("over the limit: %v, want the deadline", err)
	}
	waiting := make(chan error, 1)
	go func() {
		_, err := send(context.Background(), tr, http.MethodGet, "https://b.test/", nil)
		waiting <- err
	}()
	select {
	case err := <-waiting:
		t.Fatalf("answered over the limit: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	if err := <-waiting; err != nil {
		t.Fatal(err)
	}
	if n := srv.Accepted(); n != 2 || !isClosed(srv.NextConn(t)) {
		t.Errorf("%d connections, want 2, the first closed for the second", n)
	}
}

// Close ends the waits for a slot with ErrClosed, without a dial, over TLS
// and without, where the dial runs in the context of the request.
func TestMaxConnsClose(t *testing.T) {
	for _, scheme := range []string{"https", "http"} {
		t.Run(scheme, func(t *testing.T) {
			srv, tr, arrived, release := limitLabPlain(t, 1, scheme == "http")
			defer close(release)
			go send(context.Background(), tr, http.MethodGet, scheme+"://a.test/block", nil)
			<-arrived
			waiting := make(chan error, 1)
			go func() {
				_, err := send(context.Background(), tr, http.MethodGet, scheme+"://b.test/", nil)
				waiting <- err
			}()
			time.Sleep(50 * time.Millisecond)
			tr.Close()
			select {
			case err := <-waiting:
				if !errors.Is(err, dispatch.ErrClosed) {
					t.Errorf("wait after Close: %v, want ErrClosed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the wait goes on after Close")
			}
			// The slots the closed connections free open nothing.
			time.Sleep(50 * time.Millisecond)
			if n := srv.Accepted(); n != 1 {
				t.Errorf("%d connections, want 1: a wait dialed after Close", n)
			}
		})
	}
}

// Of the idle connections of a host, the one used least recently closes.
func TestMaxConnsClosesLeastRecent(t *testing.T) {
	srv, tr, arrived, release := limitLab(t, 2)
	blocked := make(chan error, 1)
	go func() {
		_, err := send(context.Background(), tr, http.MethodGet, "https://a.test/block", nil)
		blocked <- err
	}()
	<-arrived
	// The second connection goes idle first, then the first.
	if _, err := send(context.Background(), tr, http.MethodGet, "https://a.test/", nil); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	if _, err := send(context.Background(), tr, http.MethodGet, "https://b.test/", nil); err != nil {
		t.Fatal(err)
	}
	first, second := srv.NextConn(t), srv.NextConn(t)
	if isClosed(first) || !isClosed(second) {
		t.Error("want the connection idle the longest closed")
	}
}

// A failed dial gives its slot back.
func TestMaxConnsFailedDial(t *testing.T) {
	_, tr, _, _ := limitLab(t, 1)
	dial := tr.DialContext
	failed := false
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !failed {
			failed = true
			return nil, errors.New("unreachable")
		}
		return dial(ctx, network, addr)
	}
	if _, err := send(context.Background(), tr, http.MethodGet, "https://a.test/", nil); err == nil {
		t.Fatal("the first dial did not fail")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := send(ctx, tr, http.MethodGet, "https://a.test/", nil); err != nil {
		t.Fatalf("after a failed dial: %v", err)
	}
}

// The connections of NewConnPerRequest share the limit of the transport.
func TestMaxConnsPerRequest(t *testing.T) {
	_, tr, arrived, release := limitLab(t, 1)
	tr.NewConnPerRequest = true
	blocked := make(chan error, 1)
	go func() {
		_, err := send(context.Background(), tr, http.MethodGet, "https://a.test/block", nil)
		blocked <- err
	}()
	<-arrived
	second := make(chan error, 1)
	go func() {
		_, err := send(context.Background(), tr, http.MethodGet, "https://a.test/block", nil)
		second <- err
	}()
	select {
	case <-arrived:
		t.Fatal("a second connection over the limit")
	case <-time.After(100 * time.Millisecond):
	}
	release <- struct{}{}
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	<-arrived
	release <- struct{}{}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
}
