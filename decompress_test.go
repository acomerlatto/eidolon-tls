package eidolon_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// The client decodes gzip by default, and WithDisableDecompression reaches
// the transport.
func TestWithDisableDecompression(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	io.WriteString(zw, "plain")
	zw.Close()
	srv := lab.Start(t, lab.Options{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gz.Bytes())
	})})
	for _, tt := range []struct {
		name string
		opts []eidolon.Option
		want []byte
	}{
		{"default", nil, []byte("plain")},
		{"disabled", []eidolon.Option{eidolon.WithDisableDecompression()}, gz.Bytes()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, srv, tt.opts...)
			resp, err := c.Get("https://example.com/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !bytes.Equal(body, tt.want) {
				t.Fatalf("body %q, want %q", body, tt.want)
			}
		})
	}
}
