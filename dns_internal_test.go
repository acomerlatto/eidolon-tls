package eidolon

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"

	utls "github.com/acomerlatto/utls"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/acomerlatto/eidolon-tls/internal/dns"
)

// useSystemDNS makes conf the configuration of the system for the test.
func useSystemDNS(t *testing.T, conf dns.Config, ok bool) {
	old := systemDNS
	systemDNS = func() (dns.Config, bool) { return conf, ok }
	t.Cleanup(func() { systemDNS = old })
}

// rcodeServer answers every query over UDP with rcode and no record, and
// returns the questions it got.
func rcodeServer(t *testing.T, rcode dnsmessage.RCode) (netip.AddrPort, func() []dnsmessage.Question) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []dnsmessage.Question
	done := make(chan struct{})
	t.Cleanup(func() { conn.Close(); <-done })
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || len(m.Questions) != 1 {
				continue
			}
			mu.Lock()
			got = append(got, m.Questions[0])
			mu.Unlock()
			m.Header.Response, m.Header.RCode = true, rcode
			resp, _ := m.Pack()
			conn.WriteToUDPAddrPort(resp, from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort(), func() []dnsmessage.Question {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
}

// A direct client asks the name servers of the system for the HTTPS
// records, except for the hosts of the hosts file and localhost.
func TestSystemDNS(t *testing.T) {
	addr, questions := rcodeServer(t, dnsmessage.RCodeSuccess)
	useSystemDNS(t, dns.Config{
		Servers:  []netip.AddrPort{addr},
		Attempts: 1,
		Hosts:    map[dns.HostsKey]netip.Addr{{Name: "hosts.example", IPv6: false}: netip.MustParseAddr("192.0.2.1")},
	}, true)
	c, err := New(WithProfile(Chrome156Linux()), WithECHMode(ECHRequired))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, u := range []string{"https://a.example/", "https://a.example:8443/", "https://hosts.example/", "https://x.localhost/"} {
		if _, err := c.Get(u); !errors.Is(err, ErrECHRequired) {
			t.Errorf("Get(%s) error %v, want ErrECHRequired", u, err)
		}
	}
	want := []dnsmessage.Question{
		{Name: dnsmessage.MustNewName("a.example."), Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET},
		{Name: dnsmessage.MustNewName("_8443._https.a.example."), Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET},
	}
	if got := questions(); !slices.Equal(got, want) {
		t.Errorf("questions %v, want %v", got, want)
	}
}

// A name server that refuses the query leaves the origin without ECH, as
// a DoH server: ECHRequired fails with ErrECHRequired, and only a SERVFAIL
// with ErrDNS.
func TestSystemDNSRefused(t *testing.T) {
	for _, tt := range []struct {
		rcode dnsmessage.RCode
		want  error
	}{
		{dnsmessage.RCodeRefused, ErrECHRequired},
		{dnsmessage.RCodeFormatError, ErrECHRequired},
		{dnsmessage.RCodeServerFailure, ErrDNS},
	} {
		addr, _ := rcodeServer(t, tt.rcode)
		useSystemDNS(t, dns.Config{Servers: []netip.AddrPort{addr}, Attempts: 1}, true)
		c, err := New(WithProfile(Chrome156Linux()), WithECHMode(ECHRequired))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Get("https://a.example/"); !errors.Is(err, tt.want) || tt.want == ErrECHRequired && errors.Is(err, ErrDNS) {
			t.Errorf("%v: Get error %v, want %v", tt.rcode, err, tt.want)
		}
		c.Close()
	}
}

// The name servers of the system are used only for direct connections,
// with ECH, and a configuration Chrome resolves with its own client.
func TestSystemDNSUnused(t *testing.T) {
	conf := dns.Config{Servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}, Attempts: 1}
	unhandled := conf
	unhandled.Unhandled = true
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
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no dial") }
	chrome := WithProfile(Chrome156Linux())
	for _, tt := range []struct {
		name string
		conf dns.Config
		ok   bool
		opts []Option
		want bool
	}{
		{"direct", conf, true, []Option{chrome}, true},
		{"proxy", conf, true, []Option{chrome, WithProxy("http://127.0.0.1:1")}, false},
		{"SOCKS proxy", conf, true, []Option{chrome, WithProxy("socks5://127.0.0.1:1")}, false},
		{"dial", conf, true, []Option{chrome, WithDialContext(dial)}, false},
		{"ECHDisabled", conf, true, []Option{chrome, WithECHMode(ECHDisabled)}, false},
		{"no ECH extension", conf, true, []Option{WithClientHello(noECH)}, false},
		{"no configuration", conf, false, []Option{chrome}, false},
		{"unhandled", unhandled, true, []Option{chrome}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			useSystemDNS(t, tt.conf, tt.ok)
			c, err := New(tt.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			r := c.(*client).tr.Resolver
			if got := r != nil; got != tt.want {
				t.Fatalf("Resolver %v, want one: %v", r, tt.want)
			}
			if r == nil {
				return
			}
			if ex, ok := r.Exchanger.(*dns.Classic); !ok || !slices.Equal(ex.Config.Servers, conf.Servers) || r.Local == nil {
				t.Errorf("Resolver %+v", r)
			}
		})
	}
	// WithDoH keeps its own resolver.
	useSystemDNS(t, conf, true)
	c, err := New(chrome, WithDoH("https://doh.example/dns-query{?dns}", "127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := c.(*client).tr.Resolver.Exchanger.(*dns.DoH); !ok {
		t.Errorf("Resolver %+v, want DoH", c.(*client).tr.Resolver)
	}
}

// WithDoH does not ask for localhost, nor, without a proxy, for the names
// of the hosts file.
func TestDoHLocal(t *testing.T) {
	conf := dns.Config{Hosts: map[dns.HostsKey]netip.Addr{{Name: "hosts.example", IPv6: true}: netip.MustParseAddr("2001:db8::1")}}
	doh := WithDoH("https://doh.example/dns-query{?dns}", "127.0.0.1")
	for _, tt := range []struct {
		name  string
		ok    bool
		opts  []Option
		hosts bool
	}{
		{"direct", true, nil, true},
		{"no configuration", false, nil, false},
		{"proxy", true, []Option{WithProxy("http://127.0.0.1:1")}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ok {
				useSystemDNS(t, conf, true)
			} else {
				useSystemDNS(t, dns.Config{}, false)
			}
			c, err := New(append([]Option{WithProfile(Chrome156Linux()), doh}, tt.opts...)...)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			r := c.(*client).tr.Resolver
			if r.Local == nil || !r.Local("x.localhost") || r.Local("a.example") || r.Local("hosts.example") != tt.hosts {
				t.Errorf("Local of localhost, a.example, hosts.example wrong, want the hosts file: %v", tt.hosts)
			}
		})
	}
}

// Close closes the resolver of the client: no lookup follows.
func TestCloseResolver(t *testing.T) {
	useSystemDNS(t, dns.Config{Servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}, Attempts: 1}, true)
	c, err := New(WithProfile(Chrome156Linux()))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := c.(*client).tr.Resolver.HTTPS(context.Background(), "a.example", 443); !errors.Is(got.Err, dns.ErrClosed) {
		t.Errorf("lookup after Close: %+v", got)
	}
}

// WithMaxDNSQueries bounds the queries of the resolver of the system and
// of WithDoH.
func TestMaxDNSQueries(t *testing.T) {
	useSystemDNS(t, dns.Config{Servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}, Attempts: 1}, true)
	for _, opts := range [][]Option{
		{WithProfile(Chrome156Linux()), WithMaxDNSQueries(3)},
		{WithProfile(Chrome156Linux()), WithMaxDNSQueries(3), WithDoH("https://doh.example/dns-query{?dns}", "127.0.0.1")},
	} {
		c, err := New(opts...)
		if err != nil {
			t.Fatal(err)
		}
		if n := c.(*client).tr.Resolver.MaxQueries; n != 3 {
			t.Errorf("MaxQueries %d, want 3", n)
		}
		c.Close()
	}
}
