package eidolon_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/net/dns/dnsmessage"

	utls "github.com/acomerlatto/utls"

	eidolon "github.com/acomerlatto/eidolon-tls"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

const (
	dohHost     = "dns.test"
	dohTemplate = "https://" + dohHost + "/dns-query{?dns}"
)

// zone is a DoH server for tests: it answers the HTTPS queries of the
// names it has, NXDOMAIN to the others, and "ok" to any other request.
type zone struct {
	mu      sync.Mutex
	answers map[string]answer
	queries []string // the names asked, in order
	methods []string
}

// answer is the answer to the HTTPS query of a name: an HTTP status other
// than 200, or an rcode and records (RDATA) with a TTL of 60 s.
type answer struct {
	status  int
	rcode   dnsmessage.RCode
	records [][]byte
}

func (z *zone) set(name string, a answer) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.answers == nil {
		z.answers = make(map[string]answer)
	}
	z.answers[name] = a
}

func (z *zone) asked() []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return slices.Clone(z.queries)
}

func (z *zone) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dns-query" {
		io.WriteString(w, "ok")
		return
	}
	var q []byte
	var err error
	if r.Method == http.MethodGet {
		q, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	} else {
		q, err = io.ReadAll(r.Body)
	}
	var p dnsmessage.Parser
	h, perr := p.Start(q)
	question, qerr := p.Question()
	if err != nil || perr != nil || qerr != nil {
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}
	name := strings.TrimSuffix(question.Name.String(), ".")
	z.mu.Lock()
	z.queries = append(z.queries, name)
	z.methods = append(z.methods, r.Method)
	a, ok := z.answers[name]
	z.mu.Unlock()
	if !ok {
		a.rcode = dnsmessage.RCodeNameError
	}
	if a.status != 0 {
		w.WriteHeader(a.status)
		return
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true, RecursionAvailable: true, RCode: a.rcode})
	b.StartQuestions()
	b.Question(question)
	b.StartAnswers()
	for _, rd := range a.records {
		b.UnknownResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.UnknownResource{Type: dnsmessage.TypeHTTPS, Data: rd})
	}
	resp, _ := b.Finish()
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(resp)
}

// svcParam is a SvcParam of an HTTPS record.
type svcParam struct {
	key   uint16
	value []byte
}

// serviceRecord returns the RDATA of a ServiceMode HTTPS record whose
// target is the owner.
func serviceRecord(priority uint16, params ...svcParam) []byte {
	b := binary.BigEndian.AppendUint16(nil, priority)
	b = append(b, 0)
	for _, p := range params {
		b = binary.BigEndian.AppendUint16(b, p.key)
		b = binary.BigEndian.AppendUint16(b, uint16(len(p.value)))
		b = append(b, p.value...)
	}
	return b
}

func echParam(list []byte) svcParam { return svcParam{5, list} }

func alpnParam(ids ...string) svcParam {
	var v []byte
	for _, id := range ids {
		v = append(append(v, byte(len(id))), id...)
	}
	return svcParam{1, v}
}

// dohLab starts a lab server for the origins and the DoH server, which
// accepts ECH with a key whose list is returned, for echPublic.
func dohLab(t *testing.T, z *zone, keys ...tls.EncryptedClientHelloKey) (*lab.Server, []byte) {
	t.Helper()
	list, key, err := lab.NewECHKey(1, echPublic)
	if err != nil {
		t.Fatal(err)
	}
	if keys == nil {
		keys = []tls.EncryptedClientHelloKey{key}
	}
	cert, err := lab.NewCertificate(time.Hour, echSecret, echPublic, "other.test", dohHost)
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{
		Certificate: &cert,
		Handler:     z,
		TLS:         func(c *tls.Config) { c.EncryptedClientHelloKeys = keys },
	})
	return srv, list
}

// dohClient returns a Chrome client of the lab with WithDoH, its server
// at 127.0.0.1.
func dohClient(t *testing.T, srv *lab.Server, opts ...eidolon.Option) eidolon.HttpClient {
	t.Helper()
	return profileClient(t, srv, append([]eidolon.Option{eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithDoH(dohTemplate, "127.0.0.1")}, opts...)...)
}

// nextOrigin returns the next connection of the lab that is not to the DoH
// server.
func nextOrigin(t *testing.T, srv *lab.Server) *lab.Conn {
	t.Helper()
	for {
		c := srv.NextConn(t)
		if c.State.ServerName != dohHost {
			return c
		}
	}
}

// The HTTPS record of the origin, asked over DoH before its connection,
// gives the ECH configuration: the server accepts ECH. The answer is kept
// for its TTL, for new connections too.
func TestDoHECH(t *testing.T) {
	z := &zone{}
	srv, list := dohLab(t, z)
	z.set(echSecret, answer{records: [][]byte{serviceRecord(1, alpnParam("h2"), echParam(list))}})
	c := dohClient(t, srv)
	for range 2 {
		resp, err := echGet(c, "https://"+echSecret+"/")
		if err != nil {
			t.Fatal(err)
		}
		if !resp.TLS.ECHAccepted {
			t.Error("ECH not accepted")
		}
		c.CloseIdleConnections()
	}
	if got := z.asked(); !slices.Equal(got, []string{echSecret}) {
		t.Errorf("queries %q", got)
	}
	// The DoH connection names the server, and sends GREASE ECH; the
	// origin's names only the public name.
	doh := srv.NextConn(t)
	if doh.State.ServerName != dohHost || doh.State.ECHAccepted || !slices.Contains(helloExtensions(t, doh.ClientHello), 0xfe0d) {
		t.Errorf("DoH connection: name %q, ECH %v", doh.State.ServerName, doh.State.ECHAccepted)
	}
	conn := nextOrigin(t, srv)
	if !conn.State.ECHAccepted || bytes.Contains(conn.ClientHello, []byte(echSecret)) {
		t.Errorf("origin connection: ECH %v", conn.State.ECHAccepted)
	}
}

// The DoH request is Chrome's: GET with the padded query of ID 0, its
// minimal fields in its order, over HTTP/2 with the profile's pseudo-header
// order, at the IDLE priority of Chrome's DoH (u=4, weight 110).
func TestDoHRequestFields(t *testing.T) {
	z := &zone{}
	srv, _ := dohLab(t, z)
	c := dohClient(t, srv)
	if _, err := echGet(c, "https://"+echSecret+"/"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	doh := srv.NextConn(t)
	<-doh.Done()
	frames, err := doh.H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	var fields []lab.HeaderField
	for _, f := range frames {
		if f.Type == "HEADERS" {
			fields = f.Headers
			if f.Priority == nil || f.Priority.Weight != 109 || f.Priority.StreamDep != 0 || !f.Priority.Exclusive {
				t.Errorf("priority %+v, want weight 110, exclusive on stream 0", f.Priority)
			}
			break
		}
	}
	var names []string
	for _, f := range fields {
		names = append(names, f.Name)
		if f.Name == ":path" {
			q, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(f.Value, "/dns-query?dns="))
			if len(q)%128 != 0 || q[0] != 0 || q[1] != 0 {
				t.Errorf("query %x", q)
			}
		}
	}
	want := []string{":method", ":authority", ":scheme", ":path", "accept", "accept-language", "user-agent", "accept-encoding", "priority"}
	if !slices.Equal(names, want) {
		t.Errorf("fields %q, want %q", names, want)
	}
	for _, f := range fields {
		if v, ok := map[string]string{":method": "GET", ":authority": dohHost, "accept": "application/dns-message", "accept-language": "*", "user-agent": "Chrome", "accept-encoding": "identity", "priority": "u=4, i"}[f.Name]; ok && f.Value != v {
			t.Errorf("%s: %q, want %q", f.Name, f.Value, v)
		}
	}
}

// Over HTTP/1.1, the DoH request has Connection: keep-alive and no
// Priority, as Chrome's.
func TestDoHRequestFieldsHTTP1(t *testing.T) {
	z := &zone{}
	cert, err := lab.NewCertificate(time.Hour, echSecret, dohHost)
	if err != nil {
		t.Fatal(err)
	}
	srv := lab.Start(t, lab.Options{Certificate: &cert, Handler: z, NextProtos: []string{"http/1.1"}})
	c := dohClient(t, srv)
	if _, err := echGet(c, "https://"+echSecret+"/"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	doh := srv.NextConn(t)
	<-doh.Done()
	head, _, _ := strings.Cut(string(doh.Bytes()), "\r\n\r\n")
	path, rest, _ := strings.Cut(head, "\r\n")
	want := "Host: " + dohHost + "\r\nConnection: keep-alive\r\nAccept: application/dns-message\r\nAccept-Language: *\r\nUser-Agent: Chrome\r\nAccept-Encoding: identity"
	if !strings.HasPrefix(path, "GET /dns-query?dns=") || rest != want {
		t.Errorf("request %q", head)
	}
}

// The queries follow the protocols of the client: with WithForceHTTP1,
// they go over HTTP/1.1 to a server that offers HTTP/2.
func TestDoHProtocols(t *testing.T) {
	z := &zone{}
	srv, _ := dohLab(t, z)
	c := dohClient(t, srv, eidolon.WithForceHTTP1())
	if _, err := echGet(c, "https://"+echSecret+"/"); err != nil {
		t.Fatal(err)
	}
	if doh := srv.NextConn(t); doh.State.ServerName != dohHost || doh.State.NegotiatedProtocol != "http/1.1" {
		t.Errorf("DoH connection to %q over %q, want HTTP/1.1", doh.State.ServerName, doh.State.NegotiatedProtocol)
	}
}

// A template without the dns variable sends the queries by POST.
func TestDoHPost(t *testing.T) {
	z := &zone{}
	srv, list := dohLab(t, z)
	z.set(echSecret, answer{records: [][]byte{serviceRecord(1, echParam(list))}})
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithDoH("https://"+dohHost+"/dns-query", "127.0.0.1"))
	resp, err := echGet(c, "https://"+echSecret+"/")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.TLS.ECHAccepted || !slices.Equal(z.methods, []string{http.MethodPost}) {
		t.Errorf("ECH %v, methods %q", resp.TLS.ECHAccepted, z.methods)
	}
}

// A POST query is sent again, as Chrome's, when the reused connection is
// lost before its answer.
func TestDoHPostReplay(t *testing.T) {
	z := &zone{}
	cert, err := lab.NewCertificate(time.Hour, echSecret, dohHost)
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	srv := lab.Start(t, lab.Options{Certificate: &cert, NextProtos: []string{"http/1.1"}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dns-query" && queries.Add(1) == 2 {
			c, _, err := http.NewResponseController(w).Hijack()
			if err == nil {
				c.Close() // lost without an answer
			}
			return
		}
		z.ServeHTTP(w, r)
	})})
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithECHMode(eidolon.ECHRequired),
		eidolon.WithDoH("https://"+dohHost+"/dns-query", "127.0.0.1"))
	// Without records, ECHRequired fails each request after its answer.
	for _, u := range []string{"https://" + echSecret + "/", "https://" + echSecret + ":8443/"} {
		if _, err := c.Get(u); !errors.Is(err, eidolon.ErrECHRequired) {
			t.Fatalf("Get(%s) error %v, want ErrECHRequired", u, err)
		}
	}
	if n := queries.Load(); n != 3 || srv.Accepted() != 2 {
		t.Errorf("%d queries over %d connections, want 3 over 2", n, srv.Accepted())
	}
}

// The query of a port other than 443 is _port._https.host; an IP address
// has no query, and WithECHConfig takes the place of the query.
func TestDoHQueryNames(t *testing.T) {
	z := &zone{}
	srv, list := dohLab(t, z)
	z.set("_8443._https."+echSecret, answer{records: [][]byte{serviceRecord(1, echParam(list))}})
	c := dohClient(t, srv, eidolon.WithECHConfig("other.test", list))
	resp, err := echGet(c, "https://"+echSecret+":8443/")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.TLS.ECHAccepted {
		t.Error("port 8443: ECH not accepted")
	}
	for _, u := range []string{"https://127.0.0.1/", "https://other.test/"} {
		if _, err := echGet(c, u); err != nil {
			t.Fatal(err)
		}
	}
	if got := z.asked(); !slices.Equal(got, []string{"_8443._https." + echSecret}) {
		t.Errorf("queries %q", got)
	}
}

// Without an ECH configuration from the record, the connection sends the
// GREASE ECH of the profile in ECHAuto, and ECHRequired fails before
// connecting: with ErrDNS when the lookup failed, with ErrECHRequired
// otherwise.
func TestDoHWithoutECH(t *testing.T) {
	unusable := unusableECHList(t)
	for _, tt := range []struct {
		name     string
		answer   *answer // nil: no record
		required error
	}{
		{"NXDOMAIN", nil, eidolon.ErrECHRequired},
		{"no ech key", &answer{records: [][]byte{serviceRecord(1, alpnParam("h2"))}}, eidolon.ErrECHRequired},
		{"REFUSED", &answer{rcode: dnsmessage.RCodeRefused}, eidolon.ErrECHRequired},
		{"unusable list", &answer{records: [][]byte{serviceRecord(1, echParam(unusable))}}, eidolon.ErrECHRequired},
		{"SERVFAIL", &answer{rcode: dnsmessage.RCodeServerFailure}, eidolon.ErrDNS},
		{"DoH 500", &answer{status: 500}, eidolon.ErrDNS},
	} {
		for _, mode := range []eidolon.ECHMode{eidolon.ECHAuto, eidolon.ECHRequired} {
			z := &zone{}
			srv, _ := dohLab(t, z)
			if tt.answer != nil {
				z.set(echSecret, *tt.answer)
			}
			c := dohClient(t, srv, eidolon.WithECHMode(mode))
			resp, err := echGet(c, "https://"+echSecret+"/")
			if mode == eidolon.ECHRequired {
				if !errors.Is(err, tt.required) {
					t.Errorf("%s, required: %v, want %v", tt.name, err, tt.required)
				}
				if tt.name == "unusable list" && !errors.Is(err, utls.ErrNoUsableECHConfig) {
					t.Errorf("unusable list, required: %v does not tell why", err)
				}
				c.Close()
				srv.Close()
				for drained := false; !drained; {
					select {
					case conn := <-srv.Conns():
						if conn.State.ServerName != dohHost {
							t.Errorf("%s, required: connection to %q", tt.name, conn.State.ServerName)
						}
					default:
						drained = true
					}
				}
				continue
			}
			if err != nil {
				t.Errorf("%s: %v", tt.name, err)
				continue
			}
			conn := nextOrigin(t, srv)
			if resp.TLS.ECHAccepted || !slices.Contains(helloExtensions(t, conn.ClientHello), 0xfe0d) {
				t.Errorf("%s: no GREASE ECH", tt.name)
			}
		}
	}
}

// With ECHRequired, http:// fails before any query or connection.
func TestDoHRequiredHTTP(t *testing.T) {
	z := &zone{}
	srv, _ := dohLab(t, z)
	c := dohClient(t, srv, eidolon.WithECHMode(eidolon.ECHRequired))
	if _, err := echGet(c, "http://"+echSecret+"/"); !errors.Is(err, eidolon.ErrECHRequired) {
		t.Errorf("http://: %v", err)
	}
	if srv.Accepted() != 0 || len(z.asked()) != 0 {
		t.Errorf("%d connections, queries %q", srv.Accepted(), z.asked())
	}
}

// The pseudo-header order of the client applies to the DoH requests.
func TestDoHPseudoOrder(t *testing.T) {
	z := &zone{}
	srv, _ := dohLab(t, z)
	pseudo := []string{":path", ":scheme", ":authority", ":method"}
	c := dohClient(t, srv, eidolon.WithDefaultOrder(eidolon.Order{Pseudo: pseudo}))
	if _, err := echGet(c, "https://"+echSecret+"/"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	doh := srv.NextConn(t)
	<-doh.Done()
	frames, err := doh.H2Frames()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range frames {
		if f.Type == "HEADERS" {
			for _, h := range f.Headers[:4] {
				names = append(names, h.Name)
			}
			break
		}
	}
	if !slices.Equal(names, pseudo) {
		t.Errorf("pseudo-headers %q, want %q", names, pseudo)
	}
}

// Without a proxy, the DoH server is dialed at its addresses, in turn,
// with the port of the template; without WithDialContext, by the system.
func TestDoHBootstrap(t *testing.T) {
	z := &zone{}
	srv, _ := dohLab(t, z)
	var mu sync.Mutex
	var dialed []string
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithDoH(dohTemplate, "192.0.2.1", "127.0.0.1"),
		eidolon.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			if strings.HasPrefix(addr, "192.0.2.1:") {
				return nil, errors.New("unreachable")
			}
			return (&net.Dialer{}).DialContext(ctx, network, srv.Addr)
		}))
	if _, err := echGet(c, "https://"+echSecret+"/"); err != nil {
		t.Fatal(err)
	}
	if want := []string{"192.0.2.1:443", "127.0.0.1:443", echSecret + ":443"}; !slices.Equal(dialed, want) {
		t.Errorf("dialed %q, want %q", dialed, want)
	}
	// The system dials the address and port.
	_, port, _ := net.SplitHostPort(srv.Addr)
	sys, err := eidolon.New(eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithRootCAs(srv.RootCAs),
		eidolon.WithDoH("https://"+dohHost+":"+port+"/dns-query{?dns}", "127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer sys.Close()
	sys.Get("https://" + echSecret + ".invalid/") // the origin cannot be resolved
	if got := z.asked(); len(got) != 2 || got[1] != echSecret+".invalid" {
		t.Errorf("queries %q", got)
	}
}

// The DoH connections follow WithStrictTLS12: a server of a CBC suite is
// refused, and with ECHRequired the request fails before its connection.
func TestDoHStrictTLS12(t *testing.T) {
	z := &zone{}
	srv := lab.Start(t, lab.Options{Certificate: rsaCertificate(t), Handler: z, TLS: func(c *tls.Config) {
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}
	}})
	c := profileClient(t, srv, eidolon.WithProfile(eidolon.Chrome156Linux()), eidolon.WithDoH("https://127.0.0.1/dns-query{?dns}", "127.0.0.1"),
		eidolon.WithStrictTLS12(), eidolon.WithECHMode(eidolon.ECHRequired))
	if _, err := echGet(c, "https://"+echSecret+"/"); !errors.Is(err, eidolon.ErrDNS) || !errors.Is(err, eidolon.ErrTLS12Policy) {
		t.Errorf("%v", err)
	}
}

// unusableECHList returns an ECHConfigList whose only configuration has a
// KEM Chrome does not support.
func unusableECHList(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0xfe0d)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(1)
			b.AddUint16(0x0010) // DHKEM(P-256)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
			b.AddUint8(0)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(echPublic)) })
			b.AddUint16(0)
		})
	})
	return b.BytesOrPanic()
}

// A record whose ECHConfigList cannot be read fails the request, as
// Chrome; so does one whose services all have ECH and none an enabled
// protocol. The first service with an enabled protocol gives the
// configuration.
func TestDoHRecords(t *testing.T) {
	z := &zone{}
	srv, list := dohLab(t, z)
	z.set(echSecret, answer{records: [][]byte{serviceRecord(1, echParam([]byte{0, 1, 2}))}})
	c := dohClient(t, srv)
	if _, err := echGet(c, "https://"+echSecret+"/"); !errors.Is(err, eidolon.ErrInvalidECHConfig) {
		t.Errorf("malformed list: %v", err)
	}
	h3 := serviceRecord(1, alpnParam("h3"), svcParam{2, nil}, echParam(list))
	z.set("other.test", answer{records: [][]byte{h3, serviceRecord(2, echParam(list))}})
	c = dohClient(t, srv, eidolon.WithForceHTTP2())
	if _, err := echGet(c, "https://other.test/"); !errors.Is(err, eidolon.ErrDNS) {
		t.Errorf("no service for h2: %v", err)
	}
	// Over HTTP/1.1 the second service is used.
	c = dohClient(t, srv, eidolon.WithForceHTTP1())
	if resp, err := echGet(c, "https://other.test/"); err != nil || !resp.TLS.ECHAccepted {
		t.Errorf("http/1.1: %v", err)
	}
	// A service of h3 only is skipped, its list too.
	z.set("other.test", answer{records: [][]byte{serviceRecord(1, alpnParam("h3"), svcParam{2, nil}, echParam([]byte{0, 1, 2})), serviceRecord(2, echParam(list))}})
	c = dohClient(t, srv)
	if resp, err := echGet(c, "https://other.test/"); err != nil || !resp.TLS.ECHAccepted {
		t.Errorf("h3 first: %v", err)
	}
	// A service without ECH, with an enabled protocol, is not ECH-reliant.
	z.set("other.test", answer{records: [][]byte{h3, serviceRecord(2)}})
	c = dohClient(t, srv, eidolon.WithForceHTTP2())
	if resp, err := echGet(c, "https://other.test/"); err != nil || resp.TLS.ECHAccepted {
		t.Errorf("no ECH: %v", err)
	}
}

// A rejection of the record's configuration is retried with the retry
// configurations, without a new query.
func TestDoHRetry(t *testing.T) {
	z := &zone{}
	key := echKey(t)
	key.SendAsRetry = true
	srv, _ := dohLab(t, z, key)
	stale, _, err := lab.NewECHKey(9, echPublic)
	if err != nil {
		t.Fatal(err)
	}
	z.set(echSecret, answer{records: [][]byte{serviceRecord(1, echParam(stale))}})
	resp, err := echGet(dohClient(t, srv), "https://"+echSecret+"/")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.TLS.ECHAccepted || len(z.asked()) != 1 {
		t.Errorf("ECH %v, queries %q", resp.TLS.ECHAccepted, z.asked())
	}
}

// Behind a proxy, the DoH server and the origin are reached through it,
// by name, and the origin accepts ECH: what a direct Chrome would do.
func TestDoHProxy(t *testing.T) {
	for _, scheme := range []string{"socks5", "http"} {
		z := &zone{}
		srv, list := dohLab(t, z)
		z.set(echSecret, answer{records: [][]byte{serviceRecord(1, echParam(list))}})
		var dests func() []string
		var addr string
		if scheme == "socks5" {
			p := lab.StartSOCKS(t, srv.Addr, "", "")
			dests, addr = p.Destinations, p.Addr
		} else {
			p := lab.StartHTTPProxy(t, srv.Addr, "")
			addr = p.Addr
			dests = func() []string {
				var d []string
				for _, h := range p.Heads() {
					d = append(d, strings.Fields(h)[1])
				}
				return d
			}
		}
		c := proxyClient(t, srv, scheme+"://"+addr, eidolon.WithDoH(dohTemplate))
		resp, err := echGet(c, "https://"+echSecret+"/")
		if err != nil {
			t.Fatal(err)
		}
		if !resp.TLS.ECHAccepted {
			t.Errorf("%s: ECH not accepted", scheme)
		}
		if got, want := dests(), []string{dohHost + ":443", echSecret + ":443"}; !slices.Equal(got, want) {
			t.Errorf("%s: tunnels to %q, want %q", scheme, got, want)
		}
	}
}

// Behind a proxy without WithDoH, no record is looked up: the connection
// sends GREASE ECH, as Chrome behind a proxy.
func TestProxyWithoutDoH(t *testing.T) {
	z := &zone{}
	srv, _ := dohLab(t, z)
	p := lab.StartSOCKS(t, srv.Addr, "", "")
	resp, err := echGet(proxyClient(t, srv, "socks5://"+p.Addr), "https://"+echSecret+"/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.TLS.ECHAccepted || len(z.asked()) != 0 {
		t.Errorf("ECH %v, queries %q", resp.TLS.ECHAccepted, z.asked())
	}
}

// Requests with connections of their own share the answers of the client.
func TestDoHNewConnectionPerRequest(t *testing.T) {
	z := &zone{}
	srv, list := dohLab(t, z)
	z.set(echSecret, answer{records: [][]byte{serviceRecord(1, echParam(list))}})
	c := dohClient(t, srv, eidolon.WithNewConnectionPerRequest())
	for range 2 {
		if resp, err := echGet(c, "https://"+echSecret+"/"); err != nil || !resp.TLS.ECHAccepted {
			t.Fatalf("%v", err)
		}
	}
	if got := z.asked(); len(got) != 1 {
		t.Errorf("queries %q", got)
	}
}

// Close and CloseIdleConnections reach the DoH connections.
func TestDoHClose(t *testing.T) {
	for _, closeAll := range []bool{false, true} {
		z := &zone{}
		srv, _ := dohLab(t, z)
		c := dohClient(t, srv)
		if _, err := echGet(c, "https://"+echSecret+"/"); err != nil {
			t.Fatal(err)
		}
		if closeAll {
			c.Close()
		} else {
			c.CloseIdleConnections()
		}
		doh := srv.NextConn(t)
		select {
		case <-doh.Done():
		case <-time.After(5 * time.Second):
			t.Errorf("close %v: the DoH connection stays open", closeAll)
		}
	}
}

func TestDoHConfig(t *testing.T) {
	tls12 := func() (*utls.ClientHelloSpec, error) {
		return &utls.ClientHelloSpec{
			CipherSuites:       []uint16{utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CompressionMethods: []byte{0},
			Extensions:         []utls.TLSExtension{&utls.SNIExtension{}, &utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519}}, &utls.SupportedPointsExtension{SupportedPoints: []byte{0}}},
			TLSVersMax:         utls.VersionTLS12,
		}, nil
	}
	chrome := eidolon.WithProfile(eidolon.Chrome156Linux())
	noECH := func() (*utls.ClientHelloSpec, error) {
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
		if err != nil {
			return nil, err
		}
		spec.Extensions = slices.DeleteFunc(spec.Extensions, func(e utls.TLSExtension) bool {
			_, ok := e.(utls.EncryptedClientHelloExtension)
			return ok
		})
		return &spec, nil
	}
	if _, err := eidolon.New(eidolon.WithClientHello(noECH)); err != nil {
		t.Fatalf("profile without ECH: %v", err)
	}
	for name, opts := range map[string][]eidolon.Option{
		"bad template":     {chrome, eidolon.WithDoH("http://dns.test/dns-query", "127.0.0.1")},
		"not an IP":        {chrome, eidolon.WithDoH(dohTemplate, "dns.test")},
		"no addresses":     {chrome, eidolon.WithDoH(dohTemplate)},
		"twice":            {chrome, eidolon.WithDoH(dohTemplate, "127.0.0.1"), eidolon.WithDoH(dohTemplate, "127.0.0.1")},
		"ECHDisabled":      {chrome, eidolon.WithDoH(dohTemplate, "127.0.0.1"), eidolon.WithECHMode(eidolon.ECHDisabled)},
		"TLS 1.2 profile":  {eidolon.WithClientHello(tls12), eidolon.WithDoH(dohTemplate, "127.0.0.1")},
		"no ECH extension": {eidolon.WithClientHello(noECH), eidolon.WithDoH(dohTemplate, "127.0.0.1")},
	} {
		if _, err := eidolon.New(opts...); !errors.Is(err, eidolon.ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c, err := eidolon.New(chrome, eidolon.WithDoH(dohTemplate, "127.0.0.1", "::1"))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
