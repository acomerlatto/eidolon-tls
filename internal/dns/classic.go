package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// maxFallbackPeriod caps the fallback period (kDnsMaxFallbackPeriod).
	maxFallbackPeriod = 5 * time.Second
	// maxUDPResponse is the buffer of a UDP response, one byte over the
	// size of a message without EDNS (kMaxUDPSize + 1): a larger one is
	// read short and does not parse.
	maxUDPResponse = 512 + 1
)

// ErrTruncated reports a TCP response with the TC bit.
var ErrTruncated = errors.New("dns: truncated response over TCP")

// Classic is an Exchanger over the name servers of a Config, as Chrome's
// classic DnsTransaction: each attempt has a new random ID and goes, by
// UDP, to the next server, each server taking Attempts of them. A new
// attempt starts when the fallback period ends, the earlier ones still
// waiting, or at once when the last one fails. A truncated response is
// retried once by TCP to the same server, the other attempts dropped, and
// then no other attempt is made. Without other attempts, the query waits
// for the pending ones until ctx ends. A response with NXDOMAIN ends the
// query: the name is not completed with the search list.
//
// The fallback period is FallbackPeriod, doubled after each round of the
// servers, up to 5s: Chrome starts from the 99th percentile of the round
// trip times of the server, which it learns, and skips servers that
// failed.
type Classic struct {
	Config Config
	// Fallback replaces FallbackPeriod when not zero.
	Fallback time.Duration

	first atomic.Uint32 // first server of the next query, with Rotate
}

// period returns the fallback period of the attempt of index n.
func (c *Classic) period(n int) time.Duration {
	p := c.Fallback
	if p == 0 {
		p = FallbackPeriod
	}
	return min(p<<(n/len(c.Config.Servers)), maxFallbackPeriod)
}

// attempt is the outcome of an attempt.
type attempt struct {
	n           int // index, -1 for TCP
	query, resp []byte
	err         error
	truncated   bool
}

// Exchange sends a query for qtype of name to the servers.
func (c *Classic) Exchange(ctx context.Context, name string, qtype dnsmessage.Type) ([]byte, []byte, error) {
	servers := c.Config.Servers
	if len(servers) == 0 || c.Config.Attempts <= 0 {
		return nil, nil, errors.New("dns: no name server")
	}
	if _, err := Query(0, name, qtype, false); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	first := 0
	if c.Config.Rotate {
		first = int(c.first.Add(1)-1) % len(servers)
	}
	server := func(n int) netip.AddrPort { return servers[(first+n)%len(servers)] }
	total := len(servers) * c.Config.Attempts
	// Room for every attempt: those left behind still send their result,
	// and end with ctx.
	results := make(chan attempt, total+1)
	start := func(n int, network string, s netip.AddrPort) {
		go func() {
			q, _ := Query(uint16(rand.Uint32()), name, qtype, false)
			resp, err := exchange(ctx, network, s, q)
			r := attempt{n: n, query: q, resp: resp, err: err}
			if err == nil {
				r.truncated, r.err = check(q, resp)
			}
			results <- r
		}()
	}

	timer := time.NewTimer(c.period(0))
	defer timer.Stop()
	start(0, "udp", server(0))
	// last is the latest attempt, next the next one; tcp is set after the
	// TCP retry.
	last, next, pending, tcp := 0, 1, 1, false
	more := func() {
		start(next, "udp", server(next))
		timer.Reset(c.period(next))
		last, next, pending = next, next+1, pending+1
	}
	var err error
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-timer.C:
			if !tcp && next < total {
				more()
			}
			continue
		case r := <-results:
			if tcp && r.n >= 0 {
				continue
			}
			pending--
			switch {
			case r.truncated && !tcp:
				// The UDP attempts are dropped, and their answers ignored.
				// No attempt follows: the fallback period Chrome gives the
				// TCP retry only ends its waiting.
				tcp, last, pending = true, -1, 1
				start(-1, "tcp", server(r.n))
				continue
			case r.truncated:
				r.err = ErrTruncated
			case r.err == nil:
				return r.query, r.resp, nil
			}
			err = r.err
			if r.n == last && !tcp && next < total {
				more()
			}
		}
		if pending == 0 {
			return nil, nil, err
		}
	}
}

// check reads the header of resp, the response to query, as Chrome's
// DnsUDPAttempt: it reports a truncated response, or an error for a
// response that does not answer query or whose RCODE is a failure other
// than NXDOMAIN (FailureRcodeToNetError).
func check(query, resp []byte) (bool, error) {
	if _, _, err := match(query, resp); err != nil {
		return false, err
	}
	if resp[2]&0x02 != 0 {
		return true, nil
	}
	switch rcode := dnsmessage.RCode(resp[3] & 0xf); rcode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
		return false, nil
	default:
		return false, fmt.Errorf("dns: %v", rcode)
	}
}

// exchange sends q to s over network and reads the response.
func exchange(ctx context.Context, network string, s netip.AddrPort, q []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, s.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	if network == "udp" {
		if _, err := conn.Write(q); err != nil {
			return nil, err
		}
		buf := make([]byte, maxUDPResponse)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := conn.Write(append(msg, q...)); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
