package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// received is a query a nameServer received.
type received struct {
	network string
	query   []byte
}

// nameServer answers on UDP and TCP at one port of 127.0.0.1: answer gives
// the response to the query of number n (from 1) of its network, nil for
// none, and the delay before it.
type nameServer struct {
	addr netip.AddrPort
	mu   sync.Mutex
	got  []received
	// closed counts the TCP connections without an answer that the client
	// closed.
	closed atomic.Int32
}

type answerFunc func(network string, n int, q []byte) ([]byte, time.Duration)

func newNameServer(t *testing.T, answer answerFunc) *nameServer {
	t.Helper()
	var udp *net.UDPConn
	var tcp net.Listener
	for range 20 {
		var err error
		if udp, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
			t.Fatal(err)
		}
		if tcp, err = net.Listen("tcp", udp.LocalAddr().String()); err == nil {
			break
		}
		udp.Close()
	}
	if tcp == nil {
		t.Fatal("no port free on UDP and TCP")
	}
	s := &nameServer{addr: udp.LocalAddr().(*net.UDPAddr).AddrPort()}
	done := make(chan struct{})
	var wg sync.WaitGroup
	t.Cleanup(func() {
		close(done)
		udp.Close()
		tcp.Close()
		wg.Wait()
	})
	count := map[string]int{}
	record := func(network string, q []byte) int {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.got = append(s.got, received{network, q})
		count[network]++
		return count[network]
	}
	later := func(d time.Duration, f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-time.After(d):
				f()
			case <-done:
			}
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, from, err := udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			if resp, d := answer("udp", record("udp", q), q); resp != nil {
				later(d, func() { udp.WriteToUDPAddrPort(resp, from) })
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(conn, q); err != nil {
					return
				}
				resp, d := answer("tcp", record("tcp", q), q)
				if resp == nil {
					go func() { <-done; conn.Close() }()
					if _, err := io.Copy(io.Discard, conn); err == nil {
						s.closed.Add(1)
					}
					return
				}
				select {
				case <-time.After(d):
				case <-done:
					return
				}
				conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
			}()
		}
	}()
	return s
}

// queries returns the queries received on network.
func (s *nameServer) queries(network string) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	for _, r := range s.got {
		if r.network == network {
			out = append(out, r.query)
		}
	}
	return out
}

// found answers with an HTTPS record of the name asked for.
func found(t *testing.T, q []byte) []byte {
	n, _, _ := readName(q, 12)
	return response(t, q, dnsmessage.RCodeSuccess, []rr{https(n, 60, svc(1, ""))}, nil)
}

func withRcode(t *testing.T, q []byte, rcode dnsmessage.RCode) []byte {
	return response(t, q, rcode, nil, nil)
}

func truncated(t *testing.T, q []byte) []byte {
	resp := withRcode(t, q, dnsmessage.RCodeSuccess)
	resp[2] |= 0x02
	return resp
}

func classic(attempts int, fallback time.Duration, servers ...*nameServer) *Classic {
	c := &Classic{Config: Config{Attempts: attempts}, Fallback: fallback}
	for _, s := range servers {
		c.Config.Servers = append(c.Config.Servers, s.addr)
	}
	return c
}

func exchangeWithin(t *testing.T, c *Classic, d time.Duration) ([]byte, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return c.Exchange(ctx, "a.example", TypeHTTPS)
}

// The query is Chrome's classic one: no OPT record; the response is read
// as it came.
func TestClassicExchange(t *testing.T) {
	s := newNameServer(t, func(_ string, _ int, q []byte) ([]byte, time.Duration) { return found(t, q), 0 })
	q, resp, err := exchangeWithin(t, classic(1, time.Second, s), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := s.queries("udp")
	if len(got) != 1 || string(got[0]) != string(q) {
		t.Fatalf("server got %x, Exchange returned the query %x", got, q)
	}
	want, _ := Query(binary.BigEndian.Uint16(q), "a.example", TypeHTTPS, false)
	if string(q) != string(want) {
		t.Errorf("query %x, want %x", q, want)
	}
	if h := Parse(q, resp, "a.example", 443); h.Status != Found {
		t.Errorf("Parse = %+v", h)
	}
}

// Each attempt has a new ID.
func TestClassicIDs(t *testing.T) {
	s := newNameServer(t, func(_ string, n int, q []byte) ([]byte, time.Duration) {
		if n < 8 {
			return nil, 0
		}
		return found(t, q), 0
	})
	if _, _, err := exchangeWithin(t, classic(8, time.Millisecond, s), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	ids := map[uint16]bool{}
	for _, q := range s.queries("udp") {
		ids[binary.BigEndian.Uint16(q)] = true
	}
	// 8 IDs of 16 bits drawn at random repeat with a probability under
	// 1/2000.
	if len(ids) < 7 {
		t.Errorf("IDs %v", ids)
	}
}

// After the fallback period the next server is tried, the earlier attempt
// still waiting for its answer.
func TestClassicFallback(t *testing.T) {
	slow := newNameServer(t, func(_ string, _ int, q []byte) ([]byte, time.Duration) { return found(t, q), 300 * time.Millisecond })
	silent := newNameServer(t, func(string, int, []byte) ([]byte, time.Duration) { return nil, 0 })
	start := time.Now()
	if _, _, err := exchangeWithin(t, classic(1, 50*time.Millisecond, slow, silent), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(silent.queries("udp")) != 1 {
		t.Errorf("second server got %d queries, want 1", len(silent.queries("udp")))
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Errorf("answered after %v, before the first server", d)
	}
}

// Servers are taken in turn, each for Attempts attempts, and the fallback
// period doubles after each round.
func TestClassicRounds(t *testing.T) {
	var mu sync.Mutex
	var times []time.Time
	silent := func(string, int, []byte) ([]byte, time.Duration) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		return nil, 0
	}
	a, b := newNameServer(t, silent), newNameServer(t, silent)
	start := time.Now()
	_, _, err := exchangeWithin(t, classic(2, 100*time.Millisecond, a, b), 900*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Exchange error %v, want the deadline", err)
	}
	if len(a.queries("udp")) != 2 || len(b.queries("udp")) != 2 {
		t.Fatalf("queries %d and %d, want 2 each", len(a.queries("udp")), len(b.queries("udp")))
	}
	// Attempts at 0, 100, 200 and 400ms.
	mu.Lock()
	defer mu.Unlock()
	for i, want := range []time.Duration{0, 100, 200, 400} {
		got := times[i].Sub(start)
		if want *= time.Millisecond; got < want || got > want+80*time.Millisecond {
			t.Errorf("attempt %d at %v, want %v", i, got, want)
		}
	}
}

func TestClassicPeriod(t *testing.T) {
	c := &Classic{Config: Config{Servers: make([]netip.AddrPort, 2)}}
	for n, want := range []time.Duration{time.Second, time.Second, 2 * time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second} {
		if got := c.period(n); got != want {
			t.Errorf("period(%d) = %v, want %v", n, got, want)
		}
	}
	c.Fallback = 3 * time.Second
	if got := c.period(2); got != 5*time.Second {
		t.Errorf("period(2) with a fallback of 3s = %v, want 5s", got)
	}
}

// A failure of the latest attempt starts the next one at once; a
// malformed response and an RCODE other than
// NOERROR and NXDOMAIN are failures.
func TestClassicFailure(t *testing.T) {
	for _, tt := range []struct {
		name string
		resp func(q []byte) []byte
	}{
		{"SERVFAIL", func(q []byte) []byte { return withRcode(t, q, dnsmessage.RCodeServerFailure) }},
		{"REFUSED", func(q []byte) []byte { return withRcode(t, q, dnsmessage.RCodeRefused) }},
		{"other ID", func(q []byte) []byte { r := found(t, q); r[0] ^= 0xff; return r }},
		{"no QR", func(q []byte) []byte { r := found(t, q); r[2] &^= 0x80; return r }},
		{"other question", func(q []byte) []byte { r := found(t, q); r[len(q)-1] ^= 1; return r }},
		{"two questions", func(q []byte) []byte { r := found(t, q); r[5] = 2; return r }},
		{"short", func(q []byte) []byte { return found(t, q)[:len(q)-1] }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bad := newNameServer(t, func(_ string, _ int, q []byte) ([]byte, time.Duration) { return tt.resp(q), 0 })
			good := newNameServer(t, func(_ string, _ int, q []byte) ([]byte, time.Duration) { return found(t, q), 0 })
			start := time.Now()
			q, resp, err := exchangeWithin(t, classic(1, 10*time.Second, bad, good), 5*time.Second)
			if err != nil || Parse(q, resp, "a.example", 443).Status != Found {
				t.Fatalf("Exchange = %v, %v", Parse(q, resp, "a.example", 443), err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("answered after %v", d)
			}
		})
	}
}

// A UDP response is read up to 513 bytes: a larger one is returned short,
// and its records do not parse.
func TestClassicResponseSize(t *testing.T) {
	for _, size := range []int{513, 514, 700} {
		s := newNameServer(t, func(_ string, _ int, q []byte) ([]byte, time.Duration) {
			n, _, _ := readName(q, 12)
			r := response(t, q, dnsmessage.RCodeSuccess, []rr{https(n, 60, svc(1, ""))}, nil)
			// An unknown SvcParam fills the response to size.
			v := make([]byte, size-len(r)-4)
			return response(t, q, dnsmessage.RCodeSuccess, []rr{https(n, 60, svc(1, "", param{65000, v}))}, nil), 0
		})
		q, resp, err := exchangeWithin(t, classic(1, time.Second, s), 5*time.Second)
		if err != nil || len(resp) != min(size, 513) {
			t.Fatalf("size %d: Exchange = %d bytes, %v", size, len(resp), err)
		}
		if got, want := Parse(q, resp, "a.example", 443).Status, map[bool]Status{true: Found, false: Invalid}[size == 513]; got != want {
			t.Errorf("size %d: Parse = %v, want %v", size, got, want)
		}
	}
}

// NXDOMAIN ends the query with the response.
func TestClassicNXDomain(t *testing.T) {
	nx := newNameServer(t, func(_ string, _ int, q []byte) ([]byte, time.Duration) {
		return withRcode(t, q, dnsmessage.RCodeNameError), 0
	})
	other := newNameServer(t, func(_ string, _ int, q []byte) ([]byte, time.Duration) { return found(t, q), 0 })
	q, resp, err := exchangeWithin(t, classic(1, 10*time.Second, nx, other), 5*time.Second)
	if err != nil || resp[3]&0xf != byte(dnsmessage.RCodeNameError) || len(other.queries("udp")) != 0 {
		t.Fatalf("Exchange = %x, %x, %v; second server got %d queries", q, resp, err, len(other.queries("udp")))
	}
}

// A failure of an attempt that is no longer the latest starts nothing.
func TestClassicEarlierFailure(t *testing.T) {
	a := newNameServer(t, func(_ string, n int, q []byte) ([]byte, time.Duration) {
		if n == 1 {
			return withRcode(t, q, dnsmessage.RCodeServerFailure), 250 * time.Millisecond
		}
		return found(t, q), 0
	})
	b := newNameServer(t, func(string, int, []byte) ([]byte, time.Duration) { return nil, 0 })
	start := time.Now()
	if _, _, err := exchangeWithin(t, classic(2, 200*time.Millisecond, a, b), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	// The third attempt, to a again, starts at 400ms, not at 250ms.
	if d := time.Since(start); d < 350*time.Millisecond {
		t.Errorf("answered after %v", d)
	}
}

// When every attempt failed, the error of the last one is returned.
func TestClassicAllFail(t *testing.T) {
	fail := func(rcode dnsmessage.RCode) answerFunc {
		return func(_ string, _ int, q []byte) ([]byte, time.Duration) { return withRcode(t, q, rcode), 0 }
	}
	a, b := newNameServer(t, fail(dnsmessage.RCodeServerFailure)), newNameServer(t, fail(dnsmessage.RCodeRefused))
	_, _, err := exchangeWithin(t, classic(2, 10*time.Second, a, b), 5*time.Second)
	if err == nil || err.Error() != "dns: "+dnsmessage.RCodeRefused.String() {
		t.Fatalf("Exchange error %v", err)
	}
	if len(a.queries("udp")) != 2 || len(b.queries("udp")) != 2 {
		t.Errorf("queries %d and %d, want 2 each", len(a.queries("udp")), len(b.queries("udp")))
	}
}

// A truncated response is retried by TCP to the same server with a new
// ID.
func TestClassicTruncated(t *testing.T) {
	s := newNameServer(t, func(network string, _ int, q []byte) ([]byte, time.Duration) {
		if network == "udp" {
			return truncated(t, q), 0
		}
		return found(t, q), 0
	})
	q, resp, err := exchangeWithin(t, classic(1, time.Second, s), 5*time.Second)
	if err != nil || Parse(q, resp, "a.example", 443).Status != Found {
		t.Fatalf("Exchange = %v, %v", Parse(q, resp, "a.example", 443), err)
	}
	udp, tcp := s.queries("udp"), s.queries("tcp")
	if len(udp) != 1 || len(tcp) != 1 || string(tcp[0]) != string(q) || string(udp[0][:2]) == string(q[:2]) {
		t.Errorf("UDP %x, TCP %x, query %x", udp, tcp, q)
	}
}

// The TCP retry cancels the other attempts, whose late answers are
// ignored, and no attempt follows it: the query waits for it.
func TestClassicTruncatedAlone(t *testing.T) {
	a := newNameServer(t, func(network string, _ int, q []byte) ([]byte, time.Duration) {
		if network == "udp" {
			return truncated(t, q), 100 * time.Millisecond
		}
		return nil, 0
	})
	b := newNameServer(t, func(_ string, _ int, q []byte) ([]byte, time.Duration) { return found(t, q), 200 * time.Millisecond })
	start := time.Now()
	_, _, err := exchangeWithin(t, classic(3, 30*time.Millisecond, a, b), 800*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Exchange error %v, want the deadline", err)
	}
	if d := time.Since(start); d < 700*time.Millisecond {
		t.Errorf("returned after %v", d)
	}
	// Attempts at 0 (a), 30 (b), 60 (a) and 120ms (b); a answers the first
	// at 100ms.
	if n := len(a.queries("udp")) + len(b.queries("udp")); n != 3 {
		t.Errorf("%d UDP queries, want 3", n)
	}
	// The connection of the retry ends with the query.
	for deadline := time.Now().Add(2 * time.Second); a.closed.Load() != 1; {
		if time.Now().After(deadline) {
			t.Fatal("TCP connection still open")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A failed TCP retry ends the query, the dropped UDP attempts not waited
// for.
func TestClassicTruncatedFailure(t *testing.T) {
	a := newNameServer(t, func(network string, _ int, q []byte) ([]byte, time.Duration) {
		if network == "udp" {
			return truncated(t, q), 100 * time.Millisecond
		}
		return withRcode(t, q, dnsmessage.RCodeServerFailure), 0
	})
	b := newNameServer(t, func(string, int, []byte) ([]byte, time.Duration) { return nil, 0 })
	_, _, err := exchangeWithin(t, classic(1, 30*time.Millisecond, a, b), 5*time.Second)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Exchange error %v, want the SERVFAIL of the retry", err)
	}
}

// No attempt follows the TCP retry, however long its answer takes.
func TestClassicTruncatedSlow(t *testing.T) {
	a := newNameServer(t, func(network string, _ int, q []byte) ([]byte, time.Duration) {
		if network == "udp" {
			return truncated(t, q), 0
		}
		return found(t, q), 150 * time.Millisecond
	})
	b := newNameServer(t, func(string, int, []byte) ([]byte, time.Duration) { return nil, 0 })
	if _, _, err := exchangeWithin(t, classic(2, 100*time.Millisecond, a, b), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := len(b.queries("udp")); n != 0 {
		t.Errorf("second server got %d queries", n)
	}
}

// A truncated response over TCP is a failure.
func TestClassicTruncatedTCP(t *testing.T) {
	s := newNameServer(t, func(_ string, _ int, q []byte) ([]byte, time.Duration) { return truncated(t, q), 0 })
	if _, _, err := exchangeWithin(t, classic(2, time.Second, s), 5*time.Second); !errors.Is(err, ErrTruncated) {
		t.Fatalf("Exchange error %v, want ErrTruncated", err)
	}
	if n := len(s.queries("tcp")); n != 1 {
		t.Errorf("%d TCP queries, want 1", n)
	}
}

// With Rotate, each query starts on the next server.
func TestClassicRotate(t *testing.T) {
	answer := func(_ string, _ int, q []byte) ([]byte, time.Duration) { return found(t, q), 0 }
	a, b := newNameServer(t, answer), newNameServer(t, answer)
	for _, rotate := range []bool{false, true} {
		c := classic(1, time.Second, a, b)
		c.Config.Rotate = rotate
		for range 3 {
			if _, _, err := exchangeWithin(t, c, 5*time.Second); err != nil {
				t.Fatal(err)
			}
		}
	}
	if na, nb := len(a.queries("udp")), len(b.queries("udp")); na != 5 || nb != 1 {
		t.Errorf("queries %d and %d, want 5 and 1", na, nb)
	}
}

func TestClassicErrors(t *testing.T) {
	s := newNameServer(t, func(string, int, []byte) ([]byte, time.Duration) { return nil, 0 })
	if _, _, err := exchangeWithin(t, &Classic{Config: Config{Attempts: 1}}, time.Second); err == nil {
		t.Error("Exchange without servers succeeded")
	}
	if _, _, err := exchangeWithin(t, classic(0, time.Second, s), time.Second); err == nil {
		t.Error("Exchange without attempts succeeded")
	}
	if _, _, err := classic(1, time.Second, s).Exchange(context.Background(), "a..b", TypeHTTPS); err == nil {
		t.Error("Exchange of an invalid name succeeded")
	}
	if n := len(s.queries("udp")); n != 0 {
		t.Errorf("%d queries", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := classic(1, time.Second, s).Exchange(ctx, "a.example", TypeHTTPS); !errors.Is(err, context.Canceled) {
		t.Errorf("Exchange error %v, want context.Canceled", err)
	}
}

// Network errors are failures: a server that refuses the connection
// passes to the next one.
func TestClassicNetworkError(t *testing.T) {
	good := newNameServer(t, func(_ string, _ int, q []byte) ([]byte, time.Duration) { return found(t, q), 0 })
	c := classic(1, 10*time.Second, good)
	c.Config.Servers = append([]netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")}, c.Config.Servers...)
	if _, _, err := exchangeWithin(t, c, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

// Local hosts get NoData without a query.
func TestResolverLocal(t *testing.T) {
	ex, count := answering(t, dnsmessage.RCodeSuccess, https("", 60, svc(1, "")))
	c := Config{Hosts: map[HostsKey]netip.Addr{{"v4.example", false}: {}, {"v6.example", true}: {}}}
	r := &Resolver{Exchanger: ex, Local: c.Local}
	for _, host := range []string{"localhost", "localhost.", "a.localhost", "v4.example", "v6.example"} {
		if h := r.HTTPS(context.Background(), host, 443); h.Status != NoData || h.Err != nil || count(host) != 0 {
			t.Errorf("HTTPS(%s) = %+v after %d queries", host, h, count(host))
		}
	}
	for _, host := range []string{"other.example", "localhost.example", "alocalhost"} {
		if h := r.HTTPS(context.Background(), host, 443); h.Status != Found || count(host) != 1 {
			t.Errorf("HTTPS(%s) = %+v after %d queries", host, h, count(host))
		}
	}
}
