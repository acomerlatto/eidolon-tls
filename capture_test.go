package eidolon_test

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	utls "github.com/acomerlatto/utls"
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

// The profile sends what Chrome sent in the capture, over HTTP/2,
// HTTP/1.1 and http://, with the requests a page would make, in a synctest
// bubble against lab.Site, which holds each response until the page
// load of the capture would have it: the streams are open when Chrome's
// were, and the pause before the reload takes no time.
//
// Over HTTP/2, every frame but the SETTINGS ACK, whose place depends on
// when the SETTINGS of the server arrive, is that of Chrome, in order:
// the start of the connection, each HEADERS with its fields, HPACK block
// and priority, which depends on the streams still open, the DATA of the
// POST, and on the reload the PING after the first HEADERS and the
// WINDOW_UPDATE of the connection. The Akamai fingerprint and its hash are
// those of Chrome, and so is the ClientHello once normalized, with its
// JA4. Known deviation: the favicon goes at the image priority, u=2, i,
// where Chrome sent it at u=1, i, which changes the index of that field
// in its block and its weight.
//
// Over HTTP/1.1 and http://, the six subresources at once open six
// connections, the limit per host of Chrome, which TestH1PoolLimit
// checks, and each request is the one Chrome sent byte by byte; which
// connection carries which request depends on timing, there and in
// Chrome.
func TestChromeCapture(t *testing.T) {
	c := loadCapture(t)
	t.Run("h2", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var reqs []*http.Request
			for _, want := range c.H2 {
				f := map[string]string{}
				for _, kv := range want {
					f[kv[0]] = kv[1]
				}
				body := ""
				if f[":method"] == "POST" {
					body = `{"a":1}`
				}
				reqs = append(reqs, captureRequest(t, f[":method"], "https://"+f[":authority"]+f[":path"], f["referer"], f["cookie"], f["content-type"], body))
			}
			// The load of the page, then the reload: the image and the
			// script start while the stylesheet is open, and the POST of
			// the reload while the fetch is.
			l := newLoader(t, []string{"h2"}, reqs)
			l.run("s0 f0 s1 s2 s3 f1 f2 f3 s4 f4 s5 f5 s6 f6 pause s7 f7 s8 s9 s10 f8 f9 f10 s11 s12 f11 f12")
			conn := l.srv.NextConn(t)
			frames, err := conn.H2Frames()
			if err != nil {
				t.Fatal(err)
			}
			compareH2(t, c, frames)

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
	})

	for _, tt := range []struct {
		name, raw string
		protos    []string
		scheme    string
	}{{"http/1.1", c.H1, []string{"http/1.1"}, "https"}, {"http", c.Plain, nil, "http"}} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				want := splitRequests(t, tt.raw)
				var reqs []*http.Request
				for _, raw := range want {
					r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
					if err != nil {
						t.Fatal(err)
					}
					body, _ := io.ReadAll(r.Body)
					reqs = append(reqs, captureRequest(t, r.Method, tt.scheme+"://"+r.Host+r.URL.Path,
						r.Header.Get("Referer"), r.Header.Get("Cookie"), r.Header.Get("Content-Type"), string(body)))
				}
				// The page, then its six subresources at once.
				l := newLoader(t, tt.protos, reqs)
				l.run("s0 f0 s1 s2 s3 s4 s5 s6 f1 f2 f3 f4 f5 f6")
				var got []string
				for conns := 0; ; conns++ {
					select {
					case conn := <-l.srv.Conns():
						got = append(got, splitRequests(t, string(conn.Bytes()))...)
						continue
					default:
					}
					if conns != 6 {
						t.Errorf("%d connections, want 6", conns)
					}
					break
				}
				slices.Sort(got)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Errorf("sent\n%q\nwant\n%q", got, want)
				}
			})
		})
	}
}

// The ClientHellos of Chrome156Linux change from one connection to the
// next as Chrome's do, which normalHello hides: the order of the
// extensions between the first and the last, and the length of the ECH
// GREASE payload.
func TestChrome156LinuxHelloVaries(t *testing.T) {
	orders, lengths := map[string]bool{}, map[int]bool{}
	for range 32 {
		spec, err := eidolon.Chrome156Linux().ClientHello()
		if err != nil {
			t.Fatal(err)
		}
		uconn := utls.UClient(nil, &utls.Config{ServerName: "example.com"}, utls.HelloCustom)
		if err := uconn.ApplyPreset(spec); err != nil {
			t.Fatal(err)
		}
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		h := parseHello(t, uconn.HandshakeState.Hello.Raw)
		var order []string
		for _, e := range h.Extensions[1 : len(h.Extensions)-1] {
			if !fingerprint.IsGREASE(e.Type) {
				order = append(order, fmt.Sprint(e.Type))
			}
			if e.Type == 0xfe0d {
				lengths[len(e.Data)] = true
			}
		}
		orders[strings.Join(order, ",")] = true
	}
	if len(orders) < 2 || len(lengths) < 2 {
		t.Errorf("%d orders of the extensions and %d ECH lengths in 32 ClientHellos", len(orders), len(lengths))
	}
}

// compareH2 compares the frames of the HTTP/2 connection with those of
// the capture, DATA lengths included, but the known deviation of the
// favicon and the place of the SETTINGS ACK, which follows the server's
// SETTINGS: there must be exactly one. The capture keeps no payload
// length; a DATA frame has the Content-Length of its request.
func compareH2(t *testing.T, c capture, frames []lab.H2Frame) {
	t.Helper()
	describe := func(frames []lab.H2Frame) []string {
		var out []string
		for _, f := range frames {
			if f.Type == "SETTINGS" && f.Flags&1 != 0 {
				continue
			}
			s := fmt.Sprintf("%s %d %#x %v %d", f.Type, f.StreamID, f.Flags, f.Settings, f.Increment)
			if f.Priority != nil {
				s += fmt.Sprintf(" %+v", *f.Priority)
			}
			if f.Type == "DATA" {
				s += fmt.Sprintf(" of %d bytes", f.Length)
			}
			out = append(out, s)
		}
		return out
	}
	if n := len(slices.DeleteFunc(slices.Clone(frames), func(f lab.H2Frame) bool { return f.Type != "SETTINGS" || f.Flags&1 == 0 })); n != 1 {
		t.Errorf("%d SETTINGS ACK, want 1", n)
	}
	want := slices.Clone(c.H2Frames)
	length := map[uint32]uint32{} // Content-Length by stream
	i := 0
	for j, fr := range want {
		switch fr.Type {
		case "HEADERS":
			for _, kv := range c.H2[i] {
				if kv[0] == "content-length" {
					n, _ := strconv.Atoi(kv[1])
					length[fr.StreamID] = uint32(n)
				}
			}
			if slices.Contains(c.H2[i], [2]string{":path", "/favicon.ico"}) {
				p := *fr.Priority
				p.Weight = 182 // u=2, the known deviation
				want[j].Priority = &p
			}
			i++
		case "DATA":
			want[j].Length = length[fr.StreamID]
		}
	}
	if got, want := describe(frames), describe(want); !slices.Equal(got, want) {
		t.Errorf("frames:\n got %q\nwant %q", got, want)
	}
	i = 0
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
		i++
	}
	if i != len(c.H2) {
		t.Fatalf("%d requests, want %d", i, len(c.H2))
	}
}

// loader makes the requests of a page load with the Chrome profile
// against lab.Site in a synctest bubble, whose server holds each response
// until the load releases it.
type loader struct {
	t      *testing.T
	srv    *lab.Server
	client eidolon.HttpClient
	reqs   []*http.Request

	mu      sync.Mutex
	queue   map[string][]chan struct{} // by path, in the order started
	release map[int]chan struct{}      // by request
	done    map[int]chan struct{}      // by request
}

func newLoader(t *testing.T, protos []string, reqs []*http.Request) *loader {
	t.Helper()
	cert, err := lab.NewCertificate(time.Hour, lab.SiteHost, lab.SiteH1Host)
	if err != nil {
		t.Fatal(err)
	}
	l := &loader{t: t, reqs: reqs, queue: map[string][]chan struct{}{}, release: map[int]chan struct{}{}, done: map[int]chan struct{}{}}
	site := lab.Site()
	l.srv = lab.Start(t, lab.Options{NextProtos: protos, Plain: protos == nil, Certificate: &cert, Memory: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l.mu.Lock()
			q := l.queue[r.URL.Path]
			release := q[0]
			l.queue[r.URL.Path] = q[1:]
			l.mu.Unlock()
			<-release
			site.ServeHTTP(w, r)
		})})
	l.client, err = eidolon.New(
		eidolon.WithProfile(eidolon.Chrome156Linux()),
		eidolon.WithRootCAs(l.srv.RootCAs),
		eidolon.WithDialContext(l.srv.Dial),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.client.Close() })
	return l
}

// run runs the steps of a load: "sN" starts request N and waits until
// its server holds it, or until it waits for a connection; "fN" releases
// its response and waits until it is read; "pause" lets 15 s pass, more
// than the preface PING and the window update wait for.
func (l *loader) run(steps string) {
	for _, step := range strings.Fields(steps) {
		if step == "pause" {
			time.Sleep(15 * time.Second)
			continue
		}
		n, err := strconv.Atoi(step[1:])
		if err != nil {
			l.t.Fatalf("step %q", step)
		}
		l.mu.Lock()
		if step[0] == 's' {
			req := l.reqs[n]
			release, done := make(chan struct{}), make(chan struct{})
			l.queue[req.URL.Path] = append(l.queue[req.URL.Path], release)
			l.release[n], l.done[n] = release, done
			l.mu.Unlock()
			go func() {
				defer close(done)
				resp, err := l.client.Do(req)
				if err != nil {
					l.t.Errorf("request %d: %v", n, err)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}()
		} else {
			release, done := l.release[n], l.done[n]
			l.mu.Unlock()
			close(release)
			<-done
		}
		synctest.Wait()
	}
}

// splitRequests splits raw HTTP/1.1 requests, each with its body.
func splitRequests(t *testing.T, raw string) []string {
	t.Helper()
	var out []string
	for raw != "" {
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatal(err)
		}
		n := strings.Index(raw, "\r\n\r\n") + 4 + int(r.ContentLength)
		out, raw = append(out, raw[:n]), raw[n:]
	}
	return out
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
