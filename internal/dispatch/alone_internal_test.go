package dispatch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/browser"
	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
	"github.com/acomerlatto/eidolon-tls/internal/order"
	"github.com/acomerlatto/eidolon-tls/internal/proxy"
	"github.com/acomerlatto/eidolon-tls/internal/target"
)

// child copies every setting of the transport but NewConnPerRequest.
func TestChild(t *testing.T) {
	tr := &Transport{
		Spec:                   func() (*utls.ClientHelloSpec, error) { return nil, nil },
		TLS:                    &utls.Config{},
		DialContext:            func(context.Context, string, string) (net.Conn, error) { return nil, nil },
		Proxy:                  &proxy.Proxy{},
		Spelling:               http1.Spelling{"a": "A"},
		MaxConnsPerHost:        1,
		IdleConnTimeout:        time.Second,
		Order:                  &order.Order{},
		Headers:                &browser.Headers{},
		MaxResponseHeaderBytes: 1,
		DisableDecompression:   true,
		StrictTLS12:            true,
		ECH:                    map[string][]byte{"a": nil},
		ECHRequired:            true,
		Protocols:              []string{"h2"},
		H2:                     &H2Preface{},
		NewConnPerRequest:      true,
	}
	c := tr.child()
	pv, cv := reflect.ValueOf(tr).Elem(), reflect.ValueOf(c).Elem()
	for i := range pv.NumField() {
		f := pv.Type().Field(i)
		if !f.IsExported() {
			continue
		}
		p, ch := pv.Field(i), cv.Field(i)
		if p.IsZero() {
			t.Errorf("%s is not set in the test", f.Name)
		}
		switch {
		case f.Name == "NewConnPerRequest":
			if ch.Bool() {
				t.Error("the child has NewConnPerRequest")
			}
		case f.Type.Kind() == reflect.Func:
			if p.Pointer() != ch.Pointer() {
				t.Errorf("%s not copied", f.Name)
			}
		case !reflect.DeepEqual(p.Interface(), ch.Interface()):
			t.Errorf("%s not copied", f.Name)
		}
	}
}

// aloneLab returns a transport with NewConnPerRequest to a lab server for
// a.test, over protos.
func aloneLab(t *testing.T, handler http.Handler, protos ...string) (*Transport, *lab.Server) {
	t.Helper()
	cert, err := lab.NewCertificate(time.Hour, "a.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{Certificate: &cert, Handler: handler})
	tr := &Transport{
		Spec: func() (*utls.ClientHelloSpec, error) {
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
			return &spec, err
		},
		TLS: &utls.Config{RootCAs: srv.RootCAs},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Addr)
		},
		Protocols:         protos,
		NewConnPerRequest: true,
	}
	t.Cleanup(func() { tr.Close() })
	return tr, srv
}

// closed waits for the connection of srv to close and for tr to hold no
// transport of a request.
func closed(t *testing.T, tr *Transport, srv *lab.Server, what string) {
	t.Helper()
	select {
	case <-srv.NextConn(t).Done():
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: the connection stayed open", what)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.alone) != 0 {
		t.Errorf("%s: %d transports left", what, len(tr.alone))
	}
}

func get(t *testing.T, tr *Transport, method, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, "https://a.test"+path, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// The transport of a request ends when its body is read to its end, or
// closed, without the other.
func TestAloneBody(t *testing.T) {
	for _, protos := range [][]string{{"h2"}, {"http/1.1"}} {
		tr, srv := aloneLab(t, nil, protos...)
		resp := get(t, tr, "GET", "/")
		if b, err := io.ReadAll(resp.Body); err != nil || string(b) != "ok" {
			t.Fatalf("%s: body %q, %v", protos, b, err)
		}
		closed(t, tr, srv, protos[0]+" read")
		resp = get(t, tr, "GET", "/")
		resp.Body.Close()
		closed(t, tr, srv, protos[0]+" closed")
	}
}

// A response without a body ends its transport at once: a HEAD, a 204, a
// 304, and an empty body over HTTP/1.1.
func TestAloneBodyless(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/204":
			w.WriteHeader(http.StatusNoContent)
		case "/304":
			w.WriteHeader(http.StatusNotModified)
		case "/empty":
			w.Header().Set("Content-Length", "0")
		default:
			io.WriteString(w, "ok")
		}
	})
	for _, tt := range []struct {
		proto, method, path string
	}{
		{"h2", "HEAD", "/"}, {"h2", "GET", "/204"}, {"h2", "GET", "/304"}, {"http/1.1", "GET", "/empty"},
	} {
		tr, srv := aloneLab(t, handler, tt.proto)
		resp := get(t, tr, tt.method, tt.path)
		if resp.Body != http.NoBody {
			t.Errorf("%s %s %s: body %T, want http.NoBody", tt.proto, tt.method, tt.path, resp.Body)
		}
		closed(t, tr, srv, tt.proto+" "+tt.method+" "+tt.path)
	}
}

// A failed request leaves no transport, and none starts after Close.
func TestAloneErrors(t *testing.T) {
	tr, _ := aloneLab(t, nil)
	tr.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	req, _ := http.NewRequest("GET", "https://a.test/", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("the request succeeded")
	}
	tr.mu.Lock()
	if len(tr.alone) != 0 {
		t.Errorf("%d transports left", len(tr.alone))
	}
	tr.mu.Unlock()
	tr.Close()
	tgt, _ := target.Parse(req.URL)
	if _, err := tr.roundTripAlone(req, tgt); !errors.Is(err, ErrClosed) {
		t.Errorf("after Close: %v, want ErrClosed", err)
	}
}
