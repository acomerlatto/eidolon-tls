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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
}

// Server is a running lab server.
type Server struct {
	// Addr is the listening address, on 127.0.0.1.
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

// Start starts a lab server that is closed when the test ends.
func Start(tb testing.TB, opts Options) *Server {
	tb.Helper()
	if opts.NextProtos == nil {
		opts.NextProtos = []string{"h2", "http/1.1"}
	}
	if opts.Handler == nil {
		opts.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		})
	}
	cert, leaf, err := newCertificate()
	if err != nil {
		tb.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	s := &Server{
		Addr:        ln.Addr().String(),
		RootCAs:     x509.NewCertPool(),
		Certificate: leaf,
		ln:          ln,
		opts:        opts,
		conns:       make(chan *Conn, 64),
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   opts.NextProtos,
		},
	}
	s.RootCAs.AddCert(leaf)
	if opts.TLS != nil {
		opts.TLS(s.tlsConf)
	}
	s.wg.Add(1)
	go s.accept()
	tb.Cleanup(s.Close)
	return s
}

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
	defer raw.Close()
	c := &Conn{}
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
	if c.State.NegotiatedProtocol == "h2" {
		(&http2.Server{}).ServeConn(app, &http2.ServeConnOpts{Handler: s.opts.Handler})
		return
	}
	serveHTTP1(app, s.opts.Handler)
}

// serveHTTP1 serves one connection with net/http.
func serveHTTP1(c net.Conn, h http.Handler) {
	srv := &http.Server{Handler: h, ErrorLog: log.New(io.Discard, "", 0)}
	l := &oneConnListener{c: c, done: make(chan struct{})}
	srv.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateClosed || st == http.StateHijacked {
			l.close()
		}
	}
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
}

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

func (l *oneConnListener) close()         { l.once.Do(func() { close(l.done) }) }
func (l *oneConnListener) Close() error   { l.close(); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.c.LocalAddr() }

// newCertificate returns a self-signed certificate for ServerName,
// 127.0.0.1 and ::1.
func newCertificate() (tls.Certificate, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: ServerName},
		DNSNames:              []string{ServerName},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf, nil
}
