package eidolon_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// profileClient returns a client of srv with opts and no ClientHello of
// its own: it comes from the profile.
func profileClient(t *testing.T, srv *lab.Server, opts ...eidolon.Option) eidolon.HttpClient {
	t.Helper()
	base := []eidolon.Option{
		eidolon.WithRootCAs(srv.RootCAs),
		eidolon.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Addr)
		}),
	}
	c, err := eidolon.New(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// cipherSuites returns the cipher suites of a ClientHello handshake
// message.
func cipherSuites(t *testing.T, hello []byte) []uint16 {
	t.Helper()
	// type, length, version, random, session ID
	if len(hello) < 4+2+32+1 {
		t.Fatalf("short ClientHello")
	}
	b := hello[4+2+32:]
	b = b[1+int(b[0]):]
	n := int(b[0])<<8 | int(b[1])
	var out []uint16
	for i := 2; i < 2+n; i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}

// get sends a GET to url and reads the body.
func profileGet(t *testing.T, c eidolon.HttpClient, url string, header http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// The values of the capture (A10); each call returns its own copy, with
// the ClientHello of HelloChrome_155.
func TestChrome156Linux(t *testing.T) {
	p := eidolon.Chrome156Linux()
	h2 := eidolon.HTTP2Settings{
		Settings:               []eidolon.HTTP2Setting{{ID: 1, Value: 65536}, {ID: 2, Value: 0}, {ID: 4, Value: 6291456}, {ID: 6, Value: 262144}},
		ConnectionWindowUpdate: 15663105,
		Priority:               eidolon.HTTP2PriorityChromium,
		MaxDataFrameSize:       16375,
		HPACK:                  eidolon.HTTP2HPACKChromium,
		PrefacePing:            10 * time.Second,
		WindowUpdate:           eidolon.HTTP2WindowUpdateChromium,
		CancelWithoutPing:      true,
		Errors:                 eidolon.HTTP2ErrorsChromium,
		ALPS:                   eidolon.HTTP2ALPSChromium,
		HeaderFraming:          eidolon.HTTP2HeaderFramingChromium,
	}
	if p.Name != "chrome/156/linux" || !reflect.DeepEqual(p.HTTP2, h2) ||
		!slices.Equal(p.PseudoOrder, []string{":method", ":authority", ":scheme", ":path"}) ||
		!slices.Equal(p.H1Spelling, []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}) ||
		p.MaxConnsPerHost != 6 || p.IdleConnTimeout != 300*time.Second {
		t.Fatalf("%+v", p)
	}
	p.HTTP2.Settings[0].Value = 1
	p.PseudoOrder[0] = ":path"
	p.H1Spelling[0] = "SEC-CH-UA"
	p.Headers[0].Value = "x"
	p.InsecureHeaders[0].Value = "x"
	p.Dests[eidolon.FetchDocument] = eidolon.DestHeaders{Mode: "cors"}
	p.NavigationOrder[0] = "x"
	p.SubresourceOrder[0] = "x"
	q := eidolon.Chrome156Linux()
	if q.HTTP2.Settings[0].Value != 65536 || q.PseudoOrder[0] != ":method" || q.H1Spelling[0] != "sec-ch-ua" ||
		q.Headers[0].Value == "x" || q.InsecureHeaders[0].Value == "x" || q.Dests[eidolon.FetchDocument].Mode != "navigate" ||
		q.NavigationOrder[0] != "host" || q.SubresourceOrder[0] != "host" {
		t.Fatalf("copies share state: %+v", q)
	}
	spec, err := q.ClientHello()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := utls.UTLSIdToSpec(utls.HelloChrome_155)
	if !slices.Equal(spec.CipherSuites, want.CipherSuites) {
		t.Fatalf("cipher suites %v, want %v", spec.CipherSuites, want.CipherSuites)
	}
}

// The ClientHello comes from the profile; WithClientHello takes precedence,
// before or after WithProfile.
func TestProfileClientHello(t *testing.T) {
	chrome, _ := utls.UTLSIdToSpec(utls.HelloChrome_155)
	short := func() (*utls.ClientHelloSpec, error) {
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
		spec.CipherSuites = spec.CipherSuites[:4]
		return &spec, err
	}
	for _, tt := range []struct {
		name string
		opts []eidolon.Option
		want int
	}{
		{"profile", []eidolon.Option{eidolon.WithProfile(eidolon.Chrome156Linux())}, len(chrome.CipherSuites)},
		{"option after", []eidolon.Option{eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithClientHello(short)}, 4},
		{"option before", []eidolon.Option{eidolon.WithClientHello(short), eidolon.WithProfile(eidolon.Chrome156Linux())}, 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{})
			profileGet(t, profileClient(t, srv, tt.opts...), "https://example.com/", nil)
			if got := cipherSuites(t, srv.NextConn(t).ClientHello); len(got) != tt.want {
				t.Fatalf("%d cipher suites, want %d", len(got), tt.want)
			}
		})
	}
}

// The HTTP/2 preface and the pseudo-header order come from the profile;
// WithHTTP2Settings and WithDefaultOrder take precedence.
func TestProfileHTTP2(t *testing.T) {
	derived := eidolon.Chrome156Linux()
	derived.HTTP2 = pushOff(eidolon.HTTP2Settings{Settings: []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingMaxConcurrentStreams, Value: 50}}})
	derived.PseudoOrder = []string{":path", ":authority", ":scheme", ":method"}
	other := eidolon.WithHTTP2Settings(pushOff(eidolon.HTTP2Settings{Settings: []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingInitialWindowSize, Value: 70000}}}))
	order := eidolon.WithDefaultOrder(eidolon.Order{Pseudo: []string{":scheme"}})
	for _, tt := range []struct {
		name     string
		opts     []eidolon.Option
		settings []lab.Setting
		pseudo   []string
	}{
		{"profile", []eidolon.Option{eidolon.WithProfile(derived)},
			[]lab.Setting{{ID: 2, Val: 0}, {ID: 3, Val: 50}}, []string{":path", ":authority", ":scheme", ":method"}},
		{"options after", []eidolon.Option{eidolon.WithProfile(derived), other, order},
			[]lab.Setting{{ID: 2, Val: 0}, {ID: 4, Val: 70000}}, []string{":scheme", ":method", ":authority", ":path"}},
		{"options before", []eidolon.Option{other, order, eidolon.WithProfile(derived)},
			[]lab.Setting{{ID: 2, Val: 0}, {ID: 4, Val: 70000}}, []string{":scheme", ":method", ":authority", ":path"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			settings, updates, pseudo, prio := h2Preface(t, nil, tt.opts...)
			if !slices.Equal(settings, tt.settings) || updates != nil || prio != nil {
				t.Errorf("SETTINGS %v, WINDOW_UPDATE %v, priority %v; want %v and none", settings, updates, prio, tt.settings)
			}
			if !slices.Equal(pseudo, tt.pseudo) {
				t.Errorf("pseudo-headers %v, want %v", pseudo, tt.pseudo)
			}
		})
	}
}

// The HTTP/1.1 spelling comes from the profile; WithHeaderSpelling takes
// precedence.
func TestProfileH1Spelling(t *testing.T) {
	header := http.Header{"Sec-Ch-Ua": {"x"}, "X-Name": {"y"}}
	for _, tt := range []struct {
		name string
		opts []eidolon.Option
		want []string
	}{
		{"profile", []eidolon.Option{eidolon.WithProfile(eidolon.Chrome156Linux())}, []string{"\r\nsec-ch-ua: x\r\n", "\r\nX-Name: y\r\n"}},
		{"option", []eidolon.Option{eidolon.WithHeaderSpelling("x-NAME"), eidolon.WithProfile(eidolon.Chrome156Linux())},
			[]string{"\r\nSec-Ch-Ua: x\r\n", "\r\nx-NAME: y\r\n"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
			profileGet(t, profileClient(t, srv, tt.opts...), "https://example.com/", header)
			got := string(srv.NextConn(t).Bytes())
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("request %q lacks %q", got, w)
				}
			}
		})
	}
}

// The connection limits come from the profile; the options take
// precedence.
func TestProfileConnections(t *testing.T) {
	derived := eidolon.Chrome156Linux()
	derived.MaxConnsPerHost = 1
	derived.IdleConnTimeout = 300 * time.Millisecond
	loose := eidolon.Chrome156Linux()
	loose.MaxConnsPerHost = 4
	loose.IdleConnTimeout = time.Hour
	for _, tt := range []struct {
		name string
		opts []eidolon.Option
	}{
		{"profile", []eidolon.Option{eidolon.WithProfile(derived)}},
		{"options", []eidolon.Option{eidolon.WithProfile(loose), eidolon.WithMaxConnsPerHost(1), eidolon.WithIdleConnTimeout(300 * time.Millisecond)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(50 * time.Millisecond)
			})})
			c := profileClient(t, srv, tt.opts...)
			var wg sync.WaitGroup
			for range 2 {
				wg.Go(func() { profileGet(t, c, "https://example.com/", nil) })
			}
			wg.Wait()
			if n := srv.Accepted(); n != 1 {
				t.Fatalf("%d connections, want 1", n)
			}
			select {
			case <-srv.NextConn(t).Done():
			case <-time.After(5 * time.Second):
				t.Fatal("idle connection kept open")
			}
		})
	}
}

// WithProfile copies the profile: changing it afterwards does not reach
// the client.
func TestProfileCopied(t *testing.T) {
	p := eidolon.Chrome156Linux()
	opt := eidolon.WithProfile(p)
	p.HTTP2.Settings[0].Value = 1
	p.PseudoOrder[0] = ":path"
	p.Headers[3].Value = "changed"
	p.Dests[eidolon.FetchDocument] = eidolon.DestHeaders{Mode: "changed"}
	p.NavigationOrder[4] = "accept"
	settings, _, pseudo, _ := h2Preface(t, nil, opt)
	if settings[0].Val != 65536 || pseudo[0] != ":method" {
		t.Fatalf("SETTINGS %v, pseudo-headers %v", settings, pseudo)
	}
	srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
	profileGet(t, profileClient(t, srv, opt), "https://example.com/", nil)
	fields := h2Fields(t, srv.NextConn(t))
	if fields[4].Name != "sec-ch-ua" || !slices.Contains(fields, lab.HeaderField{Name: "user-agent", Value: chromeUA}) ||
		!slices.Contains(fields, lab.HeaderField{Name: "sec-fetch-mode", Value: "navigate"}) {
		t.Fatalf("fields %v", fields)
	}
}

// A profile that cannot be used is refused by New.
func TestProfileInvalid(t *testing.T) {
	for _, change := range []func(*eidolon.Profile){
		func(p *eidolon.Profile) { p.HTTP2.Priority = 9 },
		func(p *eidolon.Profile) { p.HTTP2.Settings = append(p.HTTP2.Settings, p.HTTP2.Settings[0]) },
		func(p *eidolon.Profile) { p.PseudoOrder = []string{":method", ":method"} },
		func(p *eidolon.Profile) { p.PseudoOrder = []string{"method"} },
		func(p *eidolon.Profile) { p.PseudoOrder = []string{":"} },
		func(p *eidolon.Profile) { p.H1Spelling = []string{"bad name"} },
		func(p *eidolon.Profile) {
			p.Headers = append(p.Headers, eidolon.HeaderField{Name: "bad name", Value: "1"})
		},
		func(p *eidolon.Profile) { p.InsecureHeaders[0].Value = "a\nb" },
		func(p *eidolon.Profile) { p.Dests["xhr"] = eidolon.DestHeaders{Mode: "cors"} },
		func(p *eidolon.Profile) { p.Dests[eidolon.FetchDest("font")] = eidolon.DestHeaders{} },
		func(p *eidolon.Profile) {
			p.Dests[eidolon.FetchEmpty] = eidolon.DestHeaders{Mode: "cors", Accept: "a\rb"}
		},
		func(p *eidolon.Profile) { p.NavigationOrder = append(p.NavigationOrder, "bad name") },
		func(p *eidolon.Profile) { p.SubresourceOrder = []string{""} },
		func(p *eidolon.Profile) { p.H1Connection = "a\nb" },
		func(p *eidolon.Profile) { p.MaxConnsPerHost = -1 },
		func(p *eidolon.Profile) { p.IdleConnTimeout = -1 },
	} {
		p := eidolon.Chrome156Linux()
		change(&p)
		if c, err := eidolon.New(eidolon.WithProfile(p)); !errors.Is(err, eidolon.ErrConfig) || c != nil {
			t.Errorf("New with %+v = %v, %v; want ErrConfig", p, c, err)
		}
	}
	// The zero limits keep the defaults; without a ClientHello in the
	// profile, WithClientHello gives it.
	p := eidolon.Chrome156Linux()
	p.MaxConnsPerHost, p.IdleConnTimeout = 0, 0
	if _, err := eidolon.New(eidolon.WithProfile(p)); err != nil {
		t.Fatal(err)
	}
	p.ClientHello = nil
	if _, err := eidolon.New(eidolon.WithProfile(p)); !errors.Is(err, eidolon.ErrConfig) {
		t.Fatalf("New without a ClientHello: %v", err)
	}
	if _, err := eidolon.New(eidolon.WithProfile(p), eidolon.WithClientHello(chromeSpec)); err != nil {
		t.Fatal(err)
	}
}
