package eidolon_test

import (
	"errors"
	"io"
	"testing"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// Contradictory or empty protocol sets fail in New.
func TestProtocolOptionsRejected(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts []eidolon.Option
	}{
		{"force both", []eidolon.Option{eidolon.WithForceHTTP1(), eidolon.WithForceHTTP2()}},
		{"set and force", []eidolon.Option{eidolon.WithProtocols(eidolon.HTTP1, eidolon.HTTP2), eidolon.WithForceHTTP1()}},
		{"force and set", []eidolon.Option{eidolon.WithForceHTTP2(), eidolon.WithProtocols(eidolon.HTTP2)}},
		{"empty set", []eidolon.Option{eidolon.WithProtocols()}},
		{"unknown protocol", []eidolon.Option{eidolon.WithProtocols(eidolon.Protocol(9))}},
		{"HTTP/3 only", []eidolon.Option{eidolon.WithProtocols(eidolon.HTTP3)}},
		{"HTTP/3 only, disabled", []eidolon.Option{eidolon.WithProtocols(eidolon.HTTP3), eidolon.WithDisableHTTP3()}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := append([]eidolon.Option{eidolon.WithClientHello(chromeSpec)}, tt.opts...)
			if c, err := eidolon.New(opts...); !errors.Is(err, eidolon.ErrConfig) || c != nil {
				t.Fatalf("New = %v, %v; want nil, ErrConfig", c, err)
			}
		})
	}
}

func TestProtocolOptionsAccepted(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts []eidolon.Option
	}{
		{"force HTTP/1.1 twice", []eidolon.Option{eidolon.WithForceHTTP1(), eidolon.WithForceHTTP1()}},
		{"force and disable HTTP/3", []eidolon.Option{eidolon.WithForceHTTP2(), eidolon.WithDisableHTTP3()}},
		{"set with HTTP/3 disabled", []eidolon.Option{eidolon.WithProtocols(eidolon.HTTP1, eidolon.HTTP3), eidolon.WithDisableHTTP3()}},
		{"disable HTTP/3", []eidolon.Option{eidolon.WithDisableHTTP3()}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := append([]eidolon.Option{eidolon.WithClientHello(chromeSpec)}, tt.opts...)
			c, err := eidolon.New(opts...)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
		})
	}
}

// The options reach the dispatcher: forced HTTP/1.1 against a server that
// prefers h2, forced HTTP/2 against one that only serves HTTP/1.1.
func TestProtocolOptionsApplied(t *testing.T) {
	t.Run("force HTTP/1.1", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{})
		c := newClient(t, srv, eidolon.WithForceHTTP1())
		resp, err := c.Get("https://example.com/")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 1 {
			t.Fatalf("answered over %s", resp.Proto)
		}
	})
	t.Run("force HTTP/2", func(t *testing.T) {
		srv := lab.Start(t, lab.Options{NextProtos: []string{}})
		c := newClient(t, srv, eidolon.WithForceHTTP2())
		if _, err := c.Get("https://example.com/"); !errors.Is(err, eidolon.ErrProtocolPolicy) {
			t.Fatalf("err = %v, want ErrProtocolPolicy", err)
		}
	})
}
