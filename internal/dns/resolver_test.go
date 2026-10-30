package dns

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// exchangeFunc is an Exchanger.
type exchangeFunc func(ctx context.Context, name string, qtype dnsmessage.Type) ([]byte, []byte, error)

func (f exchangeFunc) Exchange(ctx context.Context, name string, qtype dnsmessage.Type) ([]byte, []byte, error) {
	return f(ctx, name, qtype)
}

// answering returns an Exchanger that answers every query with records,
// rewritten to the name asked for, and counts the queries per name.
func answering(t *testing.T, rcode dnsmessage.RCode, records ...rr) (Exchanger, func(string) int) {
	var mu sync.Mutex
	count := make(map[string]int)
	ex := exchangeFunc(func(ctx context.Context, name string, qtype dnsmessage.Type) ([]byte, []byte, error) {
		if qtype != TypeHTTPS {
			t.Errorf("query of type %v", qtype)
		}
		mu.Lock()
		count[name]++
		mu.Unlock()
		q, err := Query(7, name, qtype, false)
		if err != nil {
			return nil, nil, err
		}
		var answers []rr
		for _, r := range records {
			r.name = name
			answers = append(answers, r)
		}
		return q, response(t, q, rcode, answers, nil), nil
	})
	return ex, func(name string) int {
		mu.Lock()
		defer mu.Unlock()
		return count[name]
	}
}

func TestQueryName(t *testing.T) {
	if got := QueryName("example.com", 443); got != "example.com" {
		t.Errorf("443: %q", got)
	}
	if got := QueryName("example.com", 8443); got != "_8443._https.example.com" {
		t.Errorf("8443: %q", got)
	}
}

// Found and NoData answers are kept for their TTL; the port of the origin
// picks the query name and the services.
func TestResolverCache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ex, queries := answering(t, dnsmessage.RCodeSuccess, https("", 60, svc(1, "", port(8443), ech1)), https("", 30, svc(2, "", ech2)))
		r := &Resolver{Exchanger: ex}
		ctx := context.Background()
		got := r.HTTPS(ctx, "example.com", 8443)
		if got.Status != Found || len(got.Services) != 2 || got.TTL != 30*time.Second {
			t.Fatalf("8443: %+v", got)
		}
		if got := r.HTTPS(ctx, "example.com", 443); len(got.Services) != 1 || string(got.Services[0].ECH) != "ech-2" {
			t.Fatalf("443: %+v", got)
		}
		time.Sleep(29 * time.Second)
		r.HTTPS(ctx, "example.com", 8443)
		if n := queries("_8443._https.example.com"); n != 1 {
			t.Errorf("within the TTL: %d queries", n)
		}
		time.Sleep(time.Second)
		if got := r.HTTPS(ctx, "example.com", 8443); got.Status != Found {
			t.Errorf("after the TTL: %+v", got)
		}
		if n := queries("_8443._https.example.com"); n != 2 {
			t.Errorf("after the TTL: %d queries", n)
		}
		// An answer without TTL does not take the place of another.
		r.MaxEntries = 1
		r.cache = nil
		r.HTTPS(ctx, "example.com", 443)
		zero, _ := answering(t, dnsmessage.RCodeSuccess, https("", 0, svc(1, "")))
		r.Exchanger = zero
		r.HTTPS(ctx, "other.test", 443)
		if _, ok := r.cache["example.com"]; !ok || len(r.cache) != 1 {
			t.Errorf("after an answer without TTL: %v", r.cache)
		}
	})
}

// Only Found and NoData answers with a TTL are kept.
func TestResolverNotCached(t *testing.T) {
	for name, ex := range map[string]Exchanger{
		"NoData without TTL": func() Exchanger { e, _ := answering(t, dnsmessage.RCodeNameError); return e }(),
		"Found without TTL":  func() Exchanger { e, _ := answering(t, dnsmessage.RCodeSuccess, https("", 0, svc(1, ""))); return e }(),
		"Incompatible": func() Exchanger {
			e, _ := answering(t, dnsmessage.RCodeSuccess, https("", 60, svc(1, "", param{0, keys(9)})))
			return e
		}(),
		"Invalid": func() Exchanger { e, _ := answering(t, dnsmessage.RCodeSuccess, https("", 60, []byte{0, 1})); return e }(),
		"Refused": func() Exchanger { e, _ := answering(t, dnsmessage.RCodeRefused); return e }(),
		"Failed":  func() Exchanger { e, _ := answering(t, dnsmessage.RCodeServerFailure); return e }(),
		"error": exchangeFunc(func(context.Context, string, dnsmessage.Type) ([]byte, []byte, error) {
			return nil, nil, errors.New("unreachable")
		}),
	} {
		var n atomic.Int32
		counted := exchangeFunc(func(ctx context.Context, q string, qt dnsmessage.Type) ([]byte, []byte, error) {
			n.Add(1)
			return ex.Exchange(ctx, q, qt)
		})
		r := &Resolver{Exchanger: counted}
		first := r.HTTPS(context.Background(), "example.com", 443)
		r.HTTPS(context.Background(), "example.com", 443)
		if n.Load() != 2 {
			t.Errorf("%s (%v): %d queries", name, first.Status, n.Load())
		}
		if name == "error" && (first.Status != Failed || first.Err == nil || first.Err.Error() != "unreachable") {
			t.Errorf("error: %+v", first)
		}
	}
	// NoData with a TTL is kept.
	synctest.Test(t, func(t *testing.T) {
		ex, queries := answering(t, dnsmessage.RCodeSuccess, https("", 45, svc(0, "a.test")))
		r := &Resolver{Exchanger: ex}
		r.HTTPS(context.Background(), "example.com", 443)
		time.Sleep(44 * time.Second)
		if got := r.HTTPS(context.Background(), "example.com", 443); got.Status != NoData || queries("example.com") != 1 {
			t.Errorf("NoData: %+v, %d queries", got, queries("example.com"))
		}
	})
}

// Concurrent lookups of a name share one query; each caller leaves at the
// end of its own context, and the query ends when the last one leaves.
func TestResolverShared(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var started atomic.Int32
		var queryCtx context.Context
		ex, _ := answering(t, dnsmessage.RCodeSuccess, https("", 60, svc(1, "")))
		r := &Resolver{Exchanger: exchangeFunc(func(ctx context.Context, n string, qt dnsmessage.Type) ([]byte, []byte, error) {
			started.Add(1)
			queryCtx = ctx
			select {
			case <-release:
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
			return ex.Exchange(ctx, n, qt)
		})}
		ctxA, cancelA := context.WithCancel(context.Background())
		results := make(chan HTTPS, 3)
		go func() { results <- r.HTTPS(ctxA, "example.com", 443) }()
		go func() { results <- r.HTTPS(context.Background(), "example.com", 443) }()
		synctest.Wait()
		cancelA()
		if got := <-results; got.Status != Failed || !errors.Is(got.Err, context.Canceled) {
			t.Errorf("canceled caller: %+v", got)
		}
		synctest.Wait()
		if queryCtx.Err() != nil {
			t.Fatal("the query ended while a caller waits")
		}
		close(release)
		if got := <-results; got.Status != Found {
			t.Errorf("remaining caller: %+v", got)
		}
		if started.Load() != 1 {
			t.Errorf("%d queries", started.Load())
		}
		// The query's context is released with its answer.
		if queryCtx.Err() == nil {
			t.Error("the context of an answered query is not released")
		}
		// The last caller to leave ends the query.
		release = make(chan struct{})
		r.cache = nil
		ctxB, cancelB := context.WithCancel(context.Background())
		go func() { results <- r.HTTPS(ctxB, "example.com", 443) }()
		synctest.Wait()
		cancelB()
		<-results
		synctest.Wait()
		if queryCtx.Err() == nil {
			t.Error("the query goes on without callers")
		}
		// A caller that leaves after the answer gets it.
		close(release)
		done, cancelD := context.WithCancel(context.Background())
		cancelD()
		r.cache = nil
		r.Exchanger = ex
		if got := r.HTTPS(done, "example.com", 443); got.Status != Failed {
			t.Errorf("canceled before the call: %+v", got)
		}
	})
}

// Close ends the queries in progress, and a lookup that needs a new query
// then fails without one; the cached answers stay.
func TestResolverClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ex, _ := answering(t, dnsmessage.RCodeSuccess, https("", 60, svc(1, "")))
		var started atomic.Int32
		r := &Resolver{Exchanger: exchangeFunc(func(ctx context.Context, n string, qt dnsmessage.Type) ([]byte, []byte, error) {
			started.Add(1)
			if n == "cached.example" {
				return ex.Exchange(ctx, n, qt)
			}
			<-ctx.Done()
			return nil, nil, ctx.Err()
		})}
		if got := r.HTTPS(context.Background(), "cached.example", 443); got.Status != Found {
			t.Fatalf("cached.example: %+v", got)
		}
		result := make(chan HTTPS, 1)
		go func() { result <- r.HTTPS(context.Background(), "example.com", 443) }()
		synctest.Wait()
		start := time.Now()
		r.Close()
		if got := <-result; got.Status != Failed || time.Since(start) != 0 {
			t.Errorf("query in progress: %+v after %v, want it ended by Close", got, time.Since(start))
		}
		if got := r.HTTPS(context.Background(), "other.example", 443); got.Status != Failed || !errors.Is(got.Err, ErrClosed) {
			t.Errorf("after Close: %+v", got)
		}
		if got := r.HTTPS(context.Background(), "cached.example", 443); got.Status != Found {
			t.Errorf("cached after Close: %+v", got)
		}
		if n := started.Load(); n != 2 {
			t.Errorf("%d queries, want 2", n)
		}
	})
}

// A caller that comes after the last one left starts another query, even
// while the canceled one has not returned, and the canceled one does not
// take the place of the other when it returns.
func TestResolverAfterCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ex, _ := answering(t, dnsmessage.RCodeSuccess, https("", 60, svc(1, "")))
		late, answer := make(chan struct{}), make(chan struct{})
		var started atomic.Int32
		r := &Resolver{Exchanger: exchangeFunc(func(ctx context.Context, n string, qt dnsmessage.Type) ([]byte, []byte, error) {
			if started.Add(1) == 1 {
				<-ctx.Done()
				<-late
				return nil, nil, ctx.Err()
			}
			<-answer
			return ex.Exchange(ctx, n, qt)
		})}
		ctx, cancel := context.WithCancel(context.Background())
		results := make(chan HTTPS, 3)
		go func() { results <- r.HTTPS(ctx, "example.com", 443) }()
		synctest.Wait()
		cancel()
		<-results
		synctest.Wait()
		go func() { results <- r.HTTPS(context.Background(), "example.com", 443) }()
		synctest.Wait()
		close(late)
		synctest.Wait()
		go func() { results <- r.HTTPS(context.Background(), "example.com", 443) }()
		synctest.Wait()
		close(answer)
		for range 2 {
			if got := <-results; got.Status != Found {
				t.Errorf("caller after the cancel: %+v", got)
			}
		}
		if started.Load() != 2 {
			t.Errorf("%d queries, want 2", started.Load())
		}
	})
}

// A query that gets no answer ends after Timeout, 12 s by default.
func TestResolverTimeout(t *testing.T) {
	for _, tt := range []struct {
		timeout, want time.Duration
	}{{0, 12 * time.Second}, {time.Second, time.Second}} {
		synctest.Test(t, func(t *testing.T) {
			r := &Resolver{Timeout: tt.timeout, Exchanger: exchangeFunc(func(ctx context.Context, _ string, _ dnsmessage.Type) ([]byte, []byte, error) {
				<-ctx.Done()
				return nil, nil, ctx.Err()
			})}
			start := time.Now()
			got := r.HTTPS(context.Background(), "example.com", 443)
			if got.Status != Failed || !errors.Is(got.Err, context.DeadlineExceeded) || time.Since(start) != tt.want {
				t.Errorf("timeout %v: %+v after %v", tt.timeout, got, time.Since(start))
			}
		})
	}
}

// A full cache drops the entry that expires first; a name already kept is
// replaced without dropping another.
func TestResolverEviction(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ttl := map[string]uint32{"a.test": 30, "b.test": 10, "c.test": 20, "d.test": 40}
		var queries sync.Map
		r := &Resolver{MaxEntries: 3, Exchanger: exchangeFunc(func(ctx context.Context, n string, qt dnsmessage.Type) ([]byte, []byte, error) {
			v, _ := queries.LoadOrStore(n, new(atomic.Int32))
			v.(*atomic.Int32).Add(1)
			q, _ := Query(1, n, qt, false)
			return q, response(t, q, dnsmessage.RCodeSuccess, []rr{https(n, ttl[n], svc(1, ""))}, nil), nil
		})}
		for _, n := range []string{"a.test", "b.test", "c.test", "c.test"} {
			r.HTTPS(context.Background(), n, 443)
		}
		r.cache["c.test"] = entry{r.cache["c.test"].https, time.Now()} // expired, still kept
		r.HTTPS(context.Background(), "c.test", 443)
		if len(r.cache) != 3 {
			t.Fatalf("%d entries", len(r.cache))
		}
		r.HTTPS(context.Background(), "d.test", 443)
		if _, ok := r.cache["b.test"]; ok || len(r.cache) != 3 {
			t.Errorf("after d.test: %v", r.cache)
		}
		ttl["e.test"] = 50
		r.HTTPS(context.Background(), "e.test", 443)
		if _, ok := r.cache["c.test"]; ok || len(r.cache) != 3 {
			t.Errorf("after e.test: %v", r.cache)
		}
		for n, want := range map[string]int32{"a.test": 1, "b.test": 1, "c.test": 2, "d.test": 1} {
			if v, _ := queries.Load(n); v.(*atomic.Int32).Load() != want {
				t.Errorf("%s: %d queries, want %d", n, v.(*atomic.Int32).Load(), want)
			}
		}
	})
	// The default limit is 1000.
	r := &Resolver{}
	for i := range DefaultMaxEntries + 1 {
		r.store(string(rune('a'+i%26))+QueryName("x", uint16(i)), entry{expires: time.Now().Add(time.Hour)})
	}
	if len(r.cache) != 1000 {
		t.Errorf("%d entries", len(r.cache))
	}
}

// A host with a final dot is asked without it, and a record whose target
// is the host applies.
func TestResolverFinalDot(t *testing.T) {
	ex, count := answering(t, dnsmessage.RCodeSuccess, https("", 60, svc(1, "a.example", alpn("h2"))))
	r := &Resolver{Exchanger: ex}
	for _, tt := range []struct {
		port uint16
		name string
	}{{443, "a.example"}, {8443, "_8443._https.a.example"}} {
		h := r.HTTPS(context.Background(), "a.example.", tt.port)
		if h.Status != Found || len(h.Services) != 1 || count(tt.name) != 1 {
			t.Errorf("HTTPS(a.example., %d) = %+v after %d queries of %s", tt.port, h, count(tt.name), tt.name)
		}
	}
}
