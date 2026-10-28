package eidolon_test

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/fingerprint"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// capture holds the requests of Chrome 156 against the lab (spec A10):
// the HEADERS of connection 001 (lab.test over HTTP/2), decoded and as
// HPACK blocks in hex, the frames of that connection without their
// payloads, and the bytes of connections 002 and 003 (h1.lab.test over
// HTTP/1.1) and 006 to 008 (plain.lab.test over http://), in the order
// they were sent. The ClientHello of connection 001 is in
// testdata/chrome156-linux-clienthello.bin.
type capture struct {
	H2       [][][2]string `json:"h2"`
	H2Blocks []string      `json:"h2_blocks"`
	H2Frames []lab.H2Frame `json:"h2_frames"`
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
// byte, the frames before the first HEADERS are those of Chrome, and so
// are the Akamai fingerprint and its hash, the weight and the exclusive
// flag of each HEADERS, and the ClientHello once normalized, with its
// JA4. The requests go one after the other, so each HEADERS depends on
// stream 0, where Chrome made some depend on a stream still open. Known
// deviation: the favicon goes at the image priority, u=2, i, where Chrome
// sent it at u=1, i, which changes the index of that field in its block
// and its weight.
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
		conn := h2.NextConn(t)
		frames, err := conn.H2Frames()
		if err != nil {
			t.Fatal(err)
		}
		if got, want := frameStart(frames), frameStart(c.H2Frames); got != want {
			t.Errorf("start of the connection:\n got %s\nwant %s", got, want)
		}
		profile := eidolon.Chrome156Linux()
		akamai := eidolon.Akamai(profile.HTTP2, profile.PseudoOrder)
		var first [][2]string
		for _, fr := range frames {
			if fr.Type == "HEADERS" {
				first = fields(fr)
				break
			}
		}
		for _, got := range []string{akamaiOf(frames, first), akamaiOf(c.H2Frames, c.H2[0])} {
			if got != akamai {
				t.Errorf("Akamai fingerprint %s, want %s", got, akamai)
			}
		}
		if sum := md5.Sum([]byte(akamai)); hex.EncodeToString(sum[:]) != "52d84b11737d980aef856699f885ca86" {
			t.Errorf("Akamai hash %x", sum)
		}
		var wantPrio []lab.Priority
		for _, fr := range c.H2Frames {
			if fr.Type == "HEADERS" {
				wantPrio = append(wantPrio, *fr.Priority)
			}
		}
		i := 0
		for _, fr := range frames {
			if fr.Type != "HEADERS" {
				continue
			}
			if i == len(c.H2) {
				t.Fatalf("more than %d requests", i)
			}
			got, want := fields(fr), [][2]string(nil)
			for _, kv := range c.H2[i] {
				if kv == [2]string{"priority", "u=1, i"} && slices.Contains(c.H2[i], [2]string{":path", "/favicon.ico"}) {
					kv[1] = "u=2, i" // the known deviation
				}
				want = append(want, kv)
			}
			if !slices.Equal(got, want) {
				t.Errorf("request %d:\n got %q\nwant %q", i, got, want)
			}
			favicon := slices.Contains(want, [2]string{":path", "/favicon.ico"})
			if block := hex.EncodeToString(fr.Block); block != c.H2Blocks[i] && !favicon {
				t.Errorf("request %d: HPACK block\n got %s\nwant %s", i, block, c.H2Blocks[i])
			}
			wp := wantPrio[i]
			if favicon {
				wp.Weight = 182 // u=2, the known deviation
			}
			if p := fr.Priority; p == nil || p.Exclusive != wp.Exclusive || p.Weight != wp.Weight || p.StreamDep != 0 {
				t.Errorf("request %d: priority %+v, want %+v on stream 0", i, p, wp)
			}
			i++
		}
		if i != len(c.H2) {
			t.Fatalf("%d requests, want %d", i, len(c.H2))
		}

		raw, err := os.ReadFile("testdata/chrome156-linux-clienthello.bin")
		if err != nil {
			t.Fatal(err)
		}
		got, want := parseHello(t, conn.ClientHello), parseHello(t, raw[5:])
		if g, w := normalHello(got), normalHello(want); g != w {
			t.Errorf("ClientHello, normalized:\n got %s\nwant %s", g, w)
		}
		if g, w := got.JA4(), want.JA4(); g != w {
			t.Errorf("JA4 %s, want %s", g, w)
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

// frameStart describes the frames before the first HEADERS, but the
// SETTINGS ACK, which goes when the SETTINGS of the server arrive: in the
// lab, they may arrive before the first request.
func frameStart(frames []lab.H2Frame) string {
	var b strings.Builder
	for _, f := range frames {
		if f.Type == "HEADERS" {
			break
		}
		if f.Type == "SETTINGS" && f.Flags&1 != 0 {
			continue
		}
		fmt.Fprintf(&b, "%s %d %#x %v %d; ", f.Type, f.StreamID, f.Flags, f.Settings, f.Increment)
	}
	return b.String()
}

// fields returns the header fields of a HEADERS frame.
func fields(fr lab.H2Frame) [][2]string {
	var out [][2]string
	for _, h := range fr.Headers {
		out = append(out, [2]string{h.Name, h.Value})
	}
	return out
}

// akamaiOf returns the Akamai fingerprint of a connection from its frames
// and the header fields of its first request.
func akamaiOf(frames []lab.H2Frame, first [][2]string) string {
	var s eidolon.HTTP2Settings
	for _, f := range frames {
		switch f.Type {
		case "SETTINGS":
			for _, st := range f.Settings {
				s.Settings = append(s.Settings, eidolon.HTTP2Setting{ID: st.ID, Value: st.Val})
			}
		case "WINDOW_UPDATE":
			s.ConnectionWindowUpdate = f.Increment
		case "PRIORITY":
			s.PriorityFrames = append(s.PriorityFrames, eidolon.HTTP2PriorityFrame{StreamID: f.StreamID,
				HTTP2PriorityParam: eidolon.HTTP2PriorityParam{StreamDep: f.Priority.StreamDep, Exclusive: f.Priority.Exclusive, Weight: f.Priority.Weight}})
		case "HEADERS":
			var pseudo []string
			for _, kv := range first {
				if strings.HasPrefix(kv[0], ":") {
					pseudo = append(pseudo, kv[0])
				}
			}
			return eidolon.Akamai(s, pseudo)
		}
	}
	return ""
}

func parseHello(t *testing.T, msg []byte) *fingerprint.ClientHello {
	t.Helper()
	h, err := fingerprint.ParseClientHello(msg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// normalHello describes h without what changes from one connection to
// the next: GREASE values become 0x0a0a, the random and the session ID
// go, and so do the key of each key share and the config ID, key and
// payload of an ECH GREASE, whose lengths stay; the length of that
// payload is one of 144, 176, 208 and 240 bytes, at random, as BoringSSL
// and uTLS draw it. Extensions are sorted by
// type, as Chrome shuffles them, but the first and the last, GREASE.
func normalHello(h *fingerprint.ClientHello) string {
	grease := func(v uint16) uint16 {
		if fingerprint.IsGREASE(v) {
			return 0x0a0a
		}
		return v
	}
	var b strings.Builder
	fmt.Fprintf(&b, "version %#04x, session ID of %d bytes, compression %x, suites", h.Version, len(h.SessionID), h.Compression)
	for _, s := range h.CipherSuites {
		fmt.Fprintf(&b, " %04x", grease(s))
	}
	exts := slices.Clone(h.Extensions)
	for i := range exts {
		exts[i].Type = grease(exts[i].Type)
	}
	if n := len(exts); n > 2 {
		slices.SortFunc(exts[1:n-1], func(a, b fingerprint.Extension) int { return int(a.Type) - int(b.Type) })
	}
	for _, e := range exts {
		fmt.Fprintf(&b, "\n%04x: ", e.Type)
		s := cryptobyte.String(e.Data)
		switch e.Type {
		case 10, 13, 43: // supported_groups, signature_algorithms, supported_versions
			n := 2
			if e.Type == 43 {
				n = 1
			}
			s.Skip(n)
			for v := uint16(0); s.ReadUint16(&v); {
				fmt.Fprintf(&b, "%04x ", grease(v))
			}
		case 51: // key_share
			var shares, key cryptobyte.String
			s.ReadUint16LengthPrefixed(&shares)
			for group := uint16(0); shares.ReadUint16(&group) && shares.ReadUint16LengthPrefixed(&key); {
				fmt.Fprintf(&b, "%04x of %d bytes ", grease(group), len(key))
			}
		case 0xfe0d: // encrypted_client_hello
			var enc, payload cryptobyte.String
			var head []byte
			if s.ReadBytes(&head, 5) && s.Skip(1) && s.ReadUint16LengthPrefixed(&enc) && s.ReadUint16LengthPrefixed(&payload) {
				n := fmt.Sprint(len(payload))
				if slices.Contains([]int{144, 176, 208, 240}, len(payload)) {
					n = "144 to 240"
				}
				fmt.Fprintf(&b, "%x, key of %d bytes, payload of %s bytes", head, len(enc), n)
			}
		}
		fmt.Fprintf(&b, "%x", []byte(s))
	}
	return b.String()
}
