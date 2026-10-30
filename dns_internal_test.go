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

// noDataServer answers every query over UDP with NOERROR and no record,
// and returns the questions it got.
func noDataServer(t *testing.T) (netip.AddrPort, func() []dnsmessage.Question) {
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
			m.Header.Response = true
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
	addr, questions := noDataServer(t)
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
