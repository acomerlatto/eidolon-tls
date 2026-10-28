// Package lab is a local server for fidelity tests. It records what a client
// sends: the raw ClientHello, and after the handshake the decrypted bytes,
// which it decodes as HTTP/2 frames or keeps as raw HTTP/1.1 requests.
//
// Captures are decoded with golang.org/x/net/http2 from upstream, not with
// the patched internal copy, so a bug in the client engine does not hide
// itself in the decoder.
package lab

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/acomerlatto/eidolon-tls/internal/http2"
)

// ServerName is the name in the lab certificate, besides 127.0.0.1 and ::1.
const ServerName = "example.com"

// Options configures a lab server.
type Options struct {
	// NextProtos are the ALPN protocols offered, in server preference
	// order. Nil offers h2 and http/1.1. HTTP/2 is served when "h2" is
	// negotiated; anything else is served as HTTP/1.1.
	NextProtos []string

	// Plain serves HTTP/1.1 over TCP, without TLS (http://).
	Plain bool

	// Handler answers the requests. Nil answers 200 with body "ok".
	Handler http.Handler

	// TLS adjusts the server TLS config (versions, curves) before use.
	TLS func(*tls.Config)

	// H2 adjusts the HTTP/2 server (MaxConcurrentStreams, ...) before each
	// connection is served.
	H2 func(*http2.Server)

	// H2Conn, if set, serves the connections that negotiate h2 instead of
	// the HTTP/2 server, with raw frames. It gets the decrypted connection
	// and closes it.
	H2Conn func(net.Conn)

	// Certificate is the server certificate. Nil generates a self-signed
	// one for ServerName, valid for one hour.
	Certificate *tls.Certificate

	// Memory serves in-memory connections, dialed with Server.Dial,
	// instead of TCP: a test in a synctest bubble, whose fake clock only
	// advances when every goroutine waits on something of the bubble,
	// starts it in the bubble.
	Memory bool
}

// Server is a running lab server.
type Server struct {
	// Addr is the listening address, on 127.0.0.1, or "memory".
	Addr string
	// RootCAs trusts the lab certificate.
	RootCAs *x509.CertPool
	// Certificate is the self-signed lab certificate.
	Certificate *x509.Certificate

	ln      net.Listener
	tlsConf *tls.Config
	opts    Options
	conns   chan *Conn

	mu   sync.Mutex
	open []net.Conn
	wg   sync.WaitGroup
}

// Accepted returns how many connections the server has accepted so far.
func (s *Server) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.open)
}

// Start starts a lab server on 127.0.0.1 that is closed when the test
// ends.
func Start(tb testing.TB, opts Options) *Server {
	tb.Helper()
	s, err := Listen("127.0.0.1:0", opts)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(s.Close)
	return s
}

// Listen starts a lab server on addr. The caller closes it, and receives
// its connections from Conns: only 64 wait there, then the server blocks.
func Listen(addr string, opts Options) (*Server, error) {
	if opts.NextProtos == nil {
		opts.NextProtos = []string{"h2", "http/1.1"}
	}
	if opts.Handler == nil {
		opts.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		})
	}
	cert := opts.Certificate
	if cert == nil {
		c, err := NewCertificate(time.Hour, ServerName)
		if err != nil {
			return nil, err
		}
		cert = &c
	}
	var ln net.Listener = &memListener{conns: make(chan net.Conn), done: make(chan struct{})}
	if !opts.Memory {
		var err error
		if ln, err = net.Listen("tcp", addr); err != nil {
			return nil, err
		}
	}
	s := &Server{
		Addr:        ln.Addr().String(),
		RootCAs:     x509.NewCertPool(),
		Certificate: cert.Leaf,
		ln:          ln,
		opts:        opts,
		conns:       make(chan *Conn, 64),
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   opts.NextProtos,
		},
	}
	s.RootCAs.AddCert(cert.Leaf)
	if opts.TLS != nil {
		opts.TLS(s.tlsConf)
	}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// Dial connects to a server with Options.Memory, as a DialContext; the
// network and address are ignored.
func (s *Server) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	ln, ok := s.ln.(*memListener)
	if !ok {
		return nil, errors.New("lab: Dial without Options.Memory")
	}
	if err := ctx.Err(); err != nil {
		return nil, err // before the select, which may accept anyway
	}
	client, server := net.Pipe()
	select {
	case ln.conns <- server:
		return client, nil
	case <-ln.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// memListener accepts the connections of Server.Dial.
type memListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *memListener) Addr() net.Addr { return memAddr{} }

type memAddr struct{}

func (memAddr) Network() string { return "memory" }
func (memAddr) String() string  { return "memory" }

// Conns returns the accepted connections, after their TLS handshake.
func (s *Server) Conns() <-chan *Conn { return s.conns }

// NextConn returns the next accepted connection, after its TLS handshake.
func (s *Server) NextConn(tb testing.TB) *Conn {
	tb.Helper()
	select {
	case c := <-s.conns:
		return c
	case <-time.After(10 * time.Second):
		tb.Fatal("lab: no connection within 10s")
		return nil
	}
}

// Close stops the server and closes every connection.
func (s *Server) Close() {
	s.ln.Close()
	s.mu.Lock()
	for _, c := range s.open {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.open = append(s.open, raw)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(raw)
		}()
	}
}

func (s *Server) serve(raw net.Conn) {
	c := &Conn{done: make(chan struct{})}
	defer close(c.done)
	defer raw.Close()
	if s.opts.Plain {
		s.conns <- c
		serveHTTP1(&recordingConn{Conn: raw, rec: &c.stream}, s.opts.Handler)
		return
	}

	hello := &recordingConn{Conn: raw, rec: &c.handshake}
	tc := tls.Server(hello, s.tlsConf)
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	err := tc.Handshake()
	raw.SetDeadline(time.Time{})
	hello.stop()
	c.ClientHello, c.ClientHelloRecord = firstClientHello(c.handshake.bytes())
	if err != nil {
		c.HandshakeErr = err
		s.conns <- c
		return
	}
	c.State = tc.ConnectionState()
	s.conns <- c

	app := &recordingTLSConn{recordingConn: recordingConn{Conn: tc, rec: &c.stream}, tc: tc}
	if c.State.NegotiatedProtocol == "h2" && s.opts.H2Conn != nil {
		s.opts.H2Conn(app)
		return
	}
	if c.State.NegotiatedProtocol == "h2" {
		h2 := &http2.Server{}
		if s.opts.H2 != nil {
			s.opts.H2(h2)
		}
		h2.ServeConn(app, &http2.ServeConnOpts{Handler: s.opts.Handler})
		return
	}
	serveHTTP1(app, s.opts.Handler)
}

// serveHTTP1 serves one connection with net/http.
func serveHTTP1(c net.Conn, h http.Handler) {
	srv := &http.Server{Handler: h, ErrorLog: log.New(io.Discard, "", 0)}
	l := &oneConnListener{done: make(chan struct{})}
	// The connection ends when it is closed: by the server, or by the
	// handler that hijacked it, which may still be writing.
	l.c = &closeHook{Conn: c, hook: l.close}
	srv.Serve(l)
	<-l.done
}

// Conn is one recorded client connection.
type Conn struct {
	// ClientHello is the first ClientHello handshake message (type, length
	// and body), reassembled if it spans several records.
	ClientHello []byte
	// ClientHelloRecord is ClientHello in a single TLS record, the input of
	// utls.Fingerprinter.
	ClientHelloRecord []byte
	// HandshakeErr is the server-side handshake error, if any.
	HandshakeErr error
	// State is the server-side TLS state.
	State tls.ConnectionState

	handshake, stream recorder
	done              chan struct{}
}

// Done is closed when the connection ends, closed by either side.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Bytes returns the bytes the client sent after the handshake, decrypted,
// as received so far.
func (c *Conn) Bytes() []byte { return c.stream.bytes() }

type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
	off bool
}

func (r *recorder) write(p []byte) {
	r.mu.Lock()
	if !r.off {
		r.buf.Write(p)
	}
	r.mu.Unlock()
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.buf.Bytes())
}

// recordingConn records what is read from the connection.
type recordingConn struct {
	net.Conn
	rec *recorder
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rec.write(p[:n])
	return n, err
}

func (c *recordingConn) stop() {
	c.rec.mu.Lock()
	c.rec.off = true
	c.rec.mu.Unlock()
}

// recordingTLSConn keeps ConnectionState visible to the HTTP/2 server.
type recordingTLSConn struct {
	recordingConn
	tc *tls.Conn
}

func (c *recordingTLSConn) ConnectionState() tls.ConnectionState { return c.tc.ConnectionState() }

// firstClientHello extracts the first handshake message from raw TLS
// records and returns it alone and wrapped in a single record.
func firstClientHello(raw []byte) (msg, record []byte) {
	var version []byte
	for len(raw) >= 5 && raw[0] == 22 { // handshake records
		n := int(raw[3])<<8 | int(raw[4])
		if len(raw) < 5+n {
			break
		}
		if version == nil {
			version = raw[1:3]
		}
		msg = append(msg, raw[5:5+n]...)
		raw = raw[5+n:]
		if len(msg) >= 4 {
			if total := 4 + (int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])); len(msg) >= total {
				msg = msg[:total]
				record = append([]byte{22, version[0], version[1], byte(total >> 8), byte(total)}, msg...)
				return msg, record
			}
		}
	}
	return nil, nil
}

type oneConnListener struct {
	c    net.Conn
	once sync.Once
	used bool
	done chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return l.c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) close() { l.once.Do(func() { close(l.done) }) }

// closeHook runs hook after the connection is closed.
type closeHook struct {
	net.Conn
	hook func()
}

func (c *closeHook) Close() error {
	err := c.Conn.Close()
	c.hook()
	return err
}
func (l *oneConnListener) Close() error   { l.close(); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.c.LocalAddr() }

// NewCertificate returns a self-signed certificate for names, 127.0.0.1
// and ::1, valid for ttl, with Leaf set.
func NewCertificate(ttl time.Duration, names ...string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
