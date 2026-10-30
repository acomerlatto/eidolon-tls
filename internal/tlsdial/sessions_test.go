package tlsdial

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"testing"
	"time"

	utls "github.com/acomerlatto/utls"
)

// sessionLog is a Sessions that keeps the last session put and records
// the calls.
type sessionLog struct {
	cs    *utls.ClientSessionState
	calls []string
}

func (l *sessionLog) Get(string) (*utls.ClientSessionState, bool) {
	l.calls = append(l.calls, "get")
	return l.cs, l.cs != nil
}

func (l *sessionLog) Put(_ string, cs *utls.ClientSessionState) {
	if cs != nil {
		l.calls = append(l.calls, "put")
		l.cs = cs
	}
}

func (l *sessionLog) Unused() { l.calls = append(l.calls, "unused") }

func (l *sessionLog) Handshake(version uint16, resumed bool) {
	l.calls = append(l.calls, fmt.Sprintf("handshake %s resumed=%v", tls.VersionName(version), resumed))
}

// exchange sends a request over conn and reads the response, after the
// TLS 1.3 tickets.
func exchange(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

// The session cache of a connection gets the sessions the server gives,
// learns at the end of the handshake whether it resumed, and gets back
// the session of a connection whose dial failed; in TLS 1.3 and 1.2.
func TestDialSessions(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			srv, _ := newTLSServer(t, []string{ProtoHTTP1}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			srv.TLS.MaxVersion = version
			log := &sessionLog{}
			cfg := Config{Spec: chromeSpec, TLS: tlsConfig(srv, "example.com"), Sessions: func() Sessions { return log }}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			dial := func(want ...string) {
				t.Helper()
				log.calls = nil
				conn, err := Dial(ctx, "tcp", srv.Listener.Addr().String(), cfg)
				if err == nil {
					exchange(t, conn)
				}
				if !slices.Equal(log.calls, want) {
					t.Errorf("calls %q, want %q", log.calls, want)
				}
			}
			// In TLS 1.2 the ticket comes in the handshake, before its
			// end; crypto/tls renews it on resumption.
			handshake := func(resumed bool) string {
				return fmt.Sprintf("handshake %s resumed=%v", tls.VersionName(version), resumed)
			}
			first, next := []string{"get", handshake(false), "put"}, []string{"get", handshake(true), "put"}
			if version == tls.VersionTLS12 {
				first, next = []string{"get", "put", handshake(false)}, []string{"get", "put", handshake(true)}
			}
			dial(first...)
			dial(next...)
			failed := errors.New("no route")
			cfg.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, failed }
			dial("get", "unused")
		})
	}
}

// A spec without the extension that would carry the session does not
// resume it: without psk_key_exchange_modes, a TLS 1.3 session goes in no
// pre_shared_key; without session_ticket, a TLS 1.2 session goes in no
// ticket.
func TestDialSessionsWithoutExtension(t *testing.T) {
	withTicket := func() (*utls.ClientHelloSpec, error) {
		spec, err := specWithALPN(ProtoHTTP1)()
		spec.Extensions = append(spec.Extensions, &utls.SessionTicketExtension{})
		return spec, err
	}
	withoutTicket := func() (*utls.ClientHelloSpec, error) {
		spec, err := chromeSpec()
		spec.Extensions = slices.DeleteFunc(spec.Extensions, func(e utls.TLSExtension) bool {
			_, ok := e.(*utls.SessionTicketExtension)
			return ok
		})
		return spec, err
	}
	for _, tt := range []struct {
		name    string
		version uint16
		spec    func() (*utls.ClientHelloSpec, error)
	}{
		{"TLS 1.3 without psk_key_exchange_modes", tls.VersionTLS13, withTicket},
		{"TLS 1.2 without session_ticket", tls.VersionTLS12, withoutTicket},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, rec := newTLSServer(t, []string{ProtoHTTP1}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			srv.TLS.MaxVersion = tt.version
			log := &sessionLog{}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for i, spec := range []func() (*utls.ClientHelloSpec, error){chromeSpec, tt.spec} {
				conn, err := Dial(ctx, "tcp", srv.Listener.Addr().String(), Config{Spec: spec, TLS: tlsConfig(srv, "example.com"), Sessions: func() Sessions { return log }})
				if err != nil {
					t.Fatal(err)
				}
				if conn.ConnectionState().DidResume {
					t.Errorf("connection %d resumed", i)
				}
				exchange(t, conn)
			}
			if exts := rec.get().Extensions; slices.Contains(exts, extPreSharedKey) {
				t.Errorf("extensions %v, with pre_shared_key", exts)
			}
		})
	}
}
