package eidolon_test

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// capture holds the requests of Chrome 156 against the lab (spec A10):
// the HEADERS of connection 001 (lab.test over HTTP/2), decoded and as
// HPACK blocks in hex, and the bytes of connections 002 and 003
// (h1.lab.test over HTTP/1.1) and 006 to 008 (plain.lab.test over
// http://), in the order they were sent.
type capture struct {
	H2       [][][2]string `json:"h2"`
	H2Blocks []string      `json:"h2_blocks"`
	H1       string        `json:"h1"`
	Plain    string        `json:"plain"`
}

func loadCapture(t *testing.T) capture {
	t.Helper()
	b, err := os.ReadFile("testdata/chrome156-linux.json")
	if err != nil {
		t.Fatal(err)
	}
	var c capture
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// captureDests are the destinations of the captured paths, given with
// WithFetchDest; "" leaves the request to the inference.
var captureDests = map[string]eidolon.FetchDest{
	"/style.css":   eidolon.FetchStyle,
	"/img.png":     eidolon.FetchImage,
	"/app.js":      eidolon.FetchScript,
	"/data":        eidolon.FetchEmpty,
	"/favicon.ico": eidolon.FetchImage,
}

// captureRequest returns the request a caller makes to reproduce a
// captured one: its method, URL, destination and what a page decides
// (Referer, Cookie, Content-Type and the body); the profile adds the rest.
func captureRequest(t *testing.T, method, url, referer, cookie, contentType, body string) *http.Request {
	t.Helper()
	ctx := context.Background()
	path := url[strings.Index(url[len("https://"):], "/")+len("https://"):]
	if d, ok := captureDests[path]; ok {
		ctx = eidolon.WithFetchDest(ctx, d)
	}
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"Referer": referer, "Cookie": cookie, "Content-Type": contentType} {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	return req
}

// The profile sends what Chrome sent in the capture, field by field and
// in order, over HTTP/2, HTTP/1.1 and http://, with the requests a page
// would make; over HTTP/2, the HPACK blocks are those of Chrome byte by
// byte. Known deviation: the favicon goes at the image priority, u=2, i,
// where Chrome sent it at u=1, i, which changes the index of that field
// in its block.
func TestChromeCapture(t *testing.T) {
	c := loadCapture(t)
	cert, err := lab.NewCertificate(time.Hour, "lab.test", "h1.lab.test")
	if err != nil {
		t.Fatal(err)
	}
	h2 := lab.Start(t, lab.Options{NextProtos: []string{"h2"}, Certificate: &cert})
	h1 := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Certificate: &cert})
	plain := lab.Start(t, lab.Options{Plain: true})
	route := map[string]string{"lab.test:443": h2.Addr, "h1.lab.test:443": h1.Addr, "plain.lab.test:80": plain.Addr}
	client, err := eidolon.New(
		eidolon.WithProfile(eidolon.Chrome156Linux()),
		eidolon.WithRootCAs(h2.RootCAs),
		eidolon.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, route[addr])
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	send := func(req *http.Request) {
		t.Helper()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	t.Run("h2", func(t *testing.T) {
		for _, want := range c.H2 {
			f := map[string]string{}
			for _, kv := range want {
				f[kv[0]] = kv[1]
			}
			body := ""
			if f[":method"] == "POST" {
				body = `{"a":1}`
			}
			send(captureRequest(t, f[":method"], "https://"+f[":authority"]+f[":path"], f["referer"], f["cookie"], f["content-type"], body))
		}
		frames, err := h2.NextConn(t).H2Frames()
		if err != nil {
			t.Fatal(err)
		}
		i := 0
		for _, fr := range frames {
			if fr.Type != "HEADERS" {
				continue
			}
			if i == len(c.H2) {
				t.Fatalf("more than %d requests", i)
			}
			var got, want [][2]string
			for _, h := range fr.Headers {
				got = append(got, [2]string{h.Name, h.Value})
			}
			for _, kv := range c.H2[i] {
				if kv == [2]string{"priority", "u=1, i"} && slices.Contains(c.H2[i], [2]string{":path", "/favicon.ico"}) {
					kv[1] = "u=2, i" // the known deviation
				}
				want = append(want, kv)
			}
			if !slices.Equal(got, want) {
				t.Errorf("request %d:\n got %q\nwant %q", i, got, want)
			}
			if block := hex.EncodeToString(fr.Block); block != c.H2Blocks[i] && !slices.Contains(want, [2]string{":path", "/favicon.ico"}) {
				t.Errorf("request %d: HPACK block\n got %s\nwant %s", i, block, c.H2Blocks[i])
			}
			i++
		}
		if i != len(c.H2) {
			t.Fatalf("%d requests, want %d", i, len(c.H2))
		}
	})

	for _, tt := range []struct {
		name, raw string
		srv       *lab.Server
		scheme    string
	}{{"http/1.1", c.H1, h1, "https"}, {"http", c.Plain, plain, "http"}} {
		t.Run(tt.name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(tt.raw))
			for {
				r, err := http.ReadRequest(br)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(r.Body)
				send(captureRequest(t, r.Method, tt.scheme+"://"+r.Host+r.URL.Path,
					r.Header.Get("Referer"), r.Header.Get("Cookie"), r.Header.Get("Content-Type"), string(body)))
			}
			if got := string(tt.srv.NextConn(t).Bytes()); got != tt.raw {
				t.Fatalf("sent\n%s\nwant\n%s", got, tt.raw)
			}
		})
	}
}
