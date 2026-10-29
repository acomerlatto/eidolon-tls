package eidolon_test

import (
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// The options copy what they are given when they are called: a change
// made before New does not reach the client.
func TestOptionsCopied(t *testing.T) {
	t.Run("WithHTTP2Settings", func(t *testing.T) {
		s := eidolon.HTTP2Settings{Settings: []eidolon.HTTP2Setting{{ID: eidolon.HTTP2SettingInitialWindowSize, Value: 70000}, {ID: eidolon.HTTP2SettingEnablePush}}}
		opt := eidolon.WithHTTP2Settings(s)
		s.Settings[0].Value = 80000
		if settings, _, _, _ := h2Preface(t, nil, opt); !slices.Equal(settings, []lab.Setting{{ID: 4, Val: 70000}, {ID: 2, Val: 0}}) {
			t.Fatalf("SETTINGS %v", settings)
		}
	})
	t.Run("WithDefaultOrder", func(t *testing.T) {
		o := eidolon.Order{Pseudo: []string{":scheme"}, Header: []string{"x-b", "x-a"}}
		opt := eidolon.WithDefaultOrder(o)
		o.Pseudo[0], o.Header[0], o.Header[1] = ":path", "x-a", "x-b"
		srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
		get(t, newClient(t, srv, opt).Do, "https://example.com/", http.Header{"X-A": {"1"}, "X-B": {"2"}})
		var names []string
		for _, n := range headerNames(t, srv.NextConn(t)) {
			if n[0] == ':' || strings.HasPrefix(n, "x-") {
				names = append(names, n)
			}
		}
		if want := []string{":scheme", ":method", ":authority", ":path", "x-b", "x-a"}; !slices.Equal(names, want) {
			t.Fatalf("order %v, want %v", names, want)
		}
	})
	t.Run("WithHeaderSpelling", func(t *testing.T) {
		names := []string{"x-NAME"}
		opt := eidolon.WithHeaderSpelling(names...)
		names[0] = "X-NAME"
		srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1"}})
		get(t, newClient(t, srv, opt).Do, "https://example.com/", http.Header{"X-Name": {"y"}})
		if got := string(srv.NextConn(t).Bytes()); !strings.Contains(got, "\r\nx-NAME: y\r\n") {
			t.Fatalf("request %q", got)
		}
	})
	t.Run("WithProtocols", func(t *testing.T) {
		ps := []eidolon.Protocol{eidolon.HTTP2}
		opt := eidolon.WithProtocols(ps...)
		ps[0] = eidolon.HTTP1
		srv := lab.Start(t, lab.Options{NextProtos: []string{"http/1.1", "h2"}})
		resp, err := newClient(t, srv, opt).Get("https://example.com/")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("%s, want HTTP/2", resp.Proto)
		}
	})
	t.Run("WithRootCAs", func(t *testing.T) {
		pool := x509.NewCertPool()
		opt := eidolon.WithRootCAs(pool)
		srv := lab.Start(t, lab.Options{NextProtos: []string{"h2"}})
		pool.AddCert(srv.Certificate)
		resp, err := newClient(t, srv, opt).Get("https://example.com/")
		if err == nil {
			resp.Body.Close()
			t.Fatal("the lab certificate was trusted")
		}
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) {
			t.Fatalf("err = %v, want an unknown authority", err)
		}
	})
}

// A WithDefaultOrder used for two clients gives each its own order: the
// pseudo-header order a profile fills in for the first does not reach the
// second.
func TestDefaultOrderReused(t *testing.T) {
	opt := eidolon.WithDefaultOrder(eidolon.Order{Header: []string{"x-a"}})
	p := eidolon.Chrome156Linux()
	p.PseudoOrder = []string{":path", ":authority", ":scheme", ":method"}
	if _, _, pseudo, _ := h2Preface(t, nil, eidolon.WithProfile(p), opt); !slices.Equal(pseudo, p.PseudoOrder) {
		t.Fatalf("with the profile: pseudo-headers %v", pseudo)
	}
	if _, _, pseudo, _ := h2Preface(t, nil, opt); !slices.Equal(pseudo, []string{":method", ":authority", ":scheme", ":path"}) {
		t.Fatalf("without it: pseudo-headers %v", pseudo)
	}
}
