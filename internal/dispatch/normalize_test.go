package dispatch_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// pathSent returns the request-target (HTTP/1.1) or :path (HTTP/2).
func pathSent(t *testing.T, c *lab.Conn) string {
	t.Helper()
	if c.State.NegotiatedProtocol != "h2" {
		line, _, _ := strings.Cut(string(c.Bytes()), "\r\n")
		parts := strings.Split(line, " ")
		if len(parts) != 3 {
			t.Fatalf("request line %q", line)
		}
		return parts[1]
	}
	frames, err := c.H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		for _, h := range f.Headers {
			if h.Name == ":path" {
				return h.Value
			}
		}
	}
	t.Fatal("no :path")
	return ""
}

// The query is percent-encoded with the URL standard's special-query set,
// as Chrome sends it, before either engine; an existing escape is kept.
// req.Host is normalized like the URL host.
func TestDispatchNormalizesQueryAndHost(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{proto}})
			tr := transport(srv)
			defer tr.Close()
			req, _ := http.NewRequest(http.MethodGet, "https://example.com/p", nil)
			req.URL.RawQuery = "q=ç&b=\"<>'&c=a b&d=%41&e=\x01\x7f&f=/?:@!$&()*+,;=~`{}|^[]\\"
			req.Host = "BÜCHER.example:443"
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			c := srv.NextConn(t)
			want := "/p?q=%C3%A7&b=%22%3C%3E%27&c=a%20b&d=%41&e=%01%7F&f=/?:@!$&()*+,;=~`{}|^[]\\"
			if got := pathSent(t, c); got != want {
				t.Errorf("target = %q, want %q", got, want)
			}
			if got := hostSent(t, c); got != "xn--bcher-kva.example" {
				t.Errorf("Host = %q, want the normalized host", got)
			}
			if req.URL.RawQuery[:2] != "q=" || req.Host[:1] != "B" {
				t.Error("caller's request changed")
			}
		})
	}
}

// After Close, an error keeps its cause as well as ErrClosed, whether the
// request is canceled too or not.
func TestDispatchClosedKeepsCause(t *testing.T) {
	for _, alsoCancel := range []bool{false, true} {
		dialing := make(chan struct{})
		tr := &dispatch.Transport{
			Spec: chromeSpec,
			TLS:  &utls.Config{},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				close(dialing)
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
		errc := make(chan error, 1)
		go func() {
			_, err := tr.RoundTrip(req)
			errc <- err
		}()
		<-dialing
		tr.Close()
		if alsoCancel {
			cancel()
		}
		select {
		case err := <-errc:
			if !errors.Is(err, dispatch.ErrClosed) || !errors.Is(err, context.Canceled) {
				t.Fatalf("request canceled %v: err = %v, want ErrClosed wrapping context.Canceled", alsoCancel, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("RoundTrip did not return")
		}
		cancel()
	}
}

// failingBody fails after its first chunk with an error that looks like a
// lost connection, as a body read from another connection would.
type failingBody struct{ reads atomic.Int32 }

func (b *failingBody) Read(p []byte) (int, error) {
	if b.reads.Add(1) == 1 {
		return copy(p, "part"), nil
	}
	return 0, io.ErrUnexpectedEOF
}

func (b *failingBody) Close() error { return nil }

// An error from the request body is not a lost connection: the request is
// not replayed even when it could be.
func TestPoolH2NoReplayOnBodyError(t *testing.T) {
	srv := lab.Start(t, lab.Options{
		NextProtos: []string{"h2"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			io.WriteString(w, "ok")
		}),
	})
	tr := transport(srv)
	defer tr.Close()
	fetch(t, tr, "https://example.com/warm")

	var getBody atomic.Int32
	req, _ := http.NewRequest(http.MethodPut, "https://example.com/", &failingBody{})
	req.ContentLength = 8
	req.Header.Set("Idempotency-Key", "k1") // replayable but for the body error
	req.GetBody = func() (io.ReadCloser, error) {
		getBody.Add(1)
		return &failingBody{}, nil
	}
	if resp, err := tr.RoundTrip(req); err == nil {
		resp.Body.Close()
		t.Fatal("request succeeded with a failing body")
	}
	if n := getBody.Load(); n != 0 {
		t.Fatalf("GetBody called %d times: the request was replayed", n)
	}
}
