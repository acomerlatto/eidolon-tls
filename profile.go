package eidolon

import (
	"errors"
	"fmt"
	"slices"
	"time"

	utls "github.com/acomerlatto/utls"
	"golang.org/x/net/http/httpguts"

	"github.com/acomerlatto/eidolon-tls/internal/browser"
	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/fetch"
	"github.com/acomerlatto/eidolon-tls/internal/http1"
	"github.com/acomerlatto/eidolon-tls/internal/order"
)

// Profile describes a browser in one version and platform: what its
// connections send and how it uses them. It is a plain value: derive one
// by copying a built-in profile and changing fields. WithProfile validates
// and copies it, so later changes do not reach a client.
type Profile struct {
	// Name identifies the profile, such as "chrome/156/linux".
	Name string
	// ClientHello returns a new ClientHello spec for each connection, as
	// WithClientHello. Without it, WithClientHello is required.
	ClientHello func() (*utls.ClientHelloSpec, error)
	// HTTP2 is what a new HTTP/2 connection sends, as WithHTTP2Settings,
	// taken as given: its zero value sends no SETTINGS parameter, no
	// WINDOW_UPDATE and no HEADERS priority.
	HTTP2 HTTP2Settings
	// PseudoOrder orders the HTTP/2 pseudo-headers, as Order.Pseudo.
	PseudoOrder []string
	// Headers are added to every https:// request and InsecureHeaders to
	// every http:// one: what the browser sends whatever the request,
	// such as User-Agent, the client hints, Accept-Encoding and
	// Accept-Language. A field of the request's Header takes the place of
	// the profile's of the same name, and a name set to nil removes it.
	// Exact mode (WithExactHeaders) sends none of the profile's headers.
	// A profile with no Headers, InsecureHeaders or Dests adds no header.
	Headers, InsecureHeaders []HeaderField
	// Dests holds the headers of each destination (WithFetchDest). Over
	// https:// a request also sends Sec-Fetch-Site, Sec-Fetch-Mode and
	// Sec-Fetch-Dest. Sec-Fetch-Site compares the initiator, the origin of
	// the Referer of the first request of a redirect chain, with each URL
	// of the chain, by origin and by site (scheme and registrable domain,
	// by the public suffix list), and sends the furthest; without a
	// Referer, a navigation sends "none" and another request counts as
	// from its own origin. Origin is sent, over https:// and http://, by
	// a method other than GET and HEAD and by a cors request to another
	// origin, as the Fetch standard says, "null" after a redirect across
	// origins. A destination not listed gets Accept */*, no
	// Priority and the Sec-Fetch-Mode the Fetch standard gives it; an
	// iframe or frame gets those of FetchDocument, without
	// Sec-Fetch-User.
	Dests map[FetchDest]DestHeaders
	// NavigationOrder orders the headers of a navigation and
	// SubresourceOrder those of the other requests, as Order.Header:
	// names the request brings, such as Referer, Cookie or Content-Type,
	// take their place there too. Over HTTP/1.1, Host and Connection go
	// where they are listed.
	NavigationOrder, SubresourceOrder []string
	// H1Connection is sent in Connection over HTTP/1.1 unless the request
	// sets one; "" sends none.
	H1Connection string
	// H1Spelling spells header names over HTTP/1.1, as
	// WithHeaderSpelling; names not listed are sent in canonical form.
	H1Spelling []string
	// MaxConnsPerHost and IdleConnTimeout are those of WithMaxConnsPerHost
	// and WithIdleConnTimeout; zero keeps the default.
	MaxConnsPerHost int
	IdleConnTimeout time.Duration
}

// DestHeaders are the headers a profile adds for one destination.
type DestHeaders struct {
	// Mode is sent in Sec-Fetch-Mode, such as "navigate", "no-cors" or
	// "cors", over https:// only.
	Mode string
	// Accept and Priority are sent as given; "" sends none. Priority is
	// never sent over HTTP/1.1, as in Chrome.
	Accept, Priority string
	// User sends Sec-Fetch-User: ?1, as a navigation the user started,
	// over https:// only.
	User bool
	// UpgradeInsecureRequests sends Upgrade-Insecure-Requests: 1.
	UpgradeInsecureRequests bool
	// Navigation orders the headers by NavigationOrder.
	Navigation bool
}

// Chrome156Linux returns the profile of Chrome 156.0.8078.73 on Linux, as
// captured on 28/10/2026: the ClientHello of the uTLS fork's
// HelloChrome_155, whose extensions are shuffled on each connection, the
// HTTP/2 SETTINGS, WINDOW_UPDATE and priority of Chrome, the pseudo-header
// order :method, :authority, :scheme, :path, the headers of a navigation,
// a fetch() and a stylesheet, image or script, over https:// and http://,
// the client hints in lowercase and Connection: keep-alive over HTTP/1.1,
// and 6 connections per host. Each call returns a new copy. Over TLS 1.2,
// the server may renegotiate any number of times over HTTP/1.1, and never
// over HTTP/2.
//
// Some positions of NavigationOrder were not captured: Content-Length,
// Cache-Control, Origin and Content-Type, which a form submitted sends.
// The image priority is that of an image in the page; Chrome sends the
// favicon at u=1, i.
func Chrome156Linux() Profile {
	return Profile{
		Name: "chrome/156/linux",
		ClientHello: func() (*utls.ClientHelloSpec, error) {
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
			for _, e := range spec.Extensions {
				if ri, ok := e.(*utls.RenegotiationInfoExtension); ok {
					// Chrome renegotiates as often as the server asks
					// (ssl_renegotiate_explicit); uTLS parrots it once.
					ri.Renegotiation = utls.RenegotiateFreelyAsClient
				}
			}
			return &spec, err
		},
		HTTP2: HTTP2Settings{
			Settings: []HTTP2Setting{
				{ID: HTTP2SettingHeaderTableSize, Value: 65536},
				{ID: HTTP2SettingEnablePush, Value: 0},
				{ID: HTTP2SettingInitialWindowSize, Value: 6291456},
				{ID: HTTP2SettingMaxHeaderListSize, Value: 262144},
			},
			ConnectionWindowUpdate: 15663105,
			Priority:               HTTP2PriorityChromium,
			MaxDataFrameSize:       16375,
			HPACK:                  HTTP2HPACKChromium,
			PrefacePing:            10 * time.Second,
			WindowUpdate:           HTTP2WindowUpdateChromium,
			CancelWithoutPing:      true,
			Errors:                 HTTP2ErrorsChromium,
			ALPS:                   HTTP2ALPSChromium,
			HeaderFraming:          HTTP2HeaderFramingChromium,
		},
		PseudoOrder: []string{":method", ":authority", ":scheme", ":path"},
		Headers: []HeaderField{
			{Name: "sec-ch-ua", Value: `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`},
			{Name: "sec-ch-ua-mobile", Value: "?0"},
			{Name: "sec-ch-ua-platform", Value: `"Linux"`},
			{Name: "user-agent", Value: chrome156UserAgent},
			{Name: "accept-encoding", Value: "gzip, deflate, br, zstd"},
			{Name: "accept-language", Value: "en-US,en;q=0.9"},
		},
		InsecureHeaders: []HeaderField{
			{Name: "user-agent", Value: chrome156UserAgent},
			{Name: "accept-encoding", Value: "gzip, deflate"},
			{Name: "accept-language", Value: "en-US,en;q=0.9"},
		},
		Dests: map[FetchDest]DestHeaders{
			FetchDocument: {
				Mode:     "navigate",
				Accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
				Priority: "u=0, i", User: true, UpgradeInsecureRequests: true, Navigation: true,
			},
			FetchStyle:  {Mode: "no-cors", Accept: "text/css,*/*;q=0.1", Priority: "u=0"},
			FetchImage:  {Mode: "no-cors", Accept: "image/jxl,image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8", Priority: "u=2, i"},
			FetchScript: {Mode: "no-cors", Accept: "*/*"},
			FetchEmpty:  {Mode: "cors", Accept: "*/*", Priority: "u=1, i"},
		},
		NavigationOrder: []string{
			"host", "connection", "content-length", "cache-control",
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "origin", "content-type",
			"upgrade-insecure-requests", "user-agent", "accept",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
			"referer", "accept-encoding", "accept-language", "cookie", "priority",
		},
		SubresourceOrder: []string{
			"host", "connection", "content-length",
			"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "content-type", "sec-ch-ua-mobile",
			"accept", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
			"referer", "accept-encoding", "accept-language", "cookie", "priority",
		},
		H1Spelling:      []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"},
		H1Connection:    "keep-alive",
		MaxConnsPerHost: dispatch.DefaultMaxConnsPerHost,
		IdleConnTimeout: dispatch.DefaultIdleConnTimeout,
	}
}

const chrome156UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"

// WithProfile sets the profile of the client. The options that set one of
// its parts, such as WithClientHello or WithHTTP2Settings, take precedence
// over that part, whatever their position. A profile that cannot be used
// returns an error that wraps ErrConfig: invalid HTTP2 (see
// WithHTTP2Settings), a pseudo-header order with a name repeated or not a
// pseudo-header, an invalid spelling (see WithHeaderSpelling), an invalid
// header name or value, a destination Sec-Fetch-Dest cannot send or
// without Mode, or a negative MaxConnsPerHost or IdleConnTimeout. The profile is copied when
// WithProfile is called.
func WithProfile(p Profile) Option {
	// Copied now: the slices of p are the caller's.
	pr, err := newProfile(p)
	return func(c *config) error {
		if err != nil {
			return fmt.Errorf("WithProfile %q: %w", p.Name, err)
		}
		c.profile = pr
		return nil
	}
}

// profile is a validated Profile, in the form of the configuration.
type profile struct {
	clientHello func() (*utls.ClientHelloSpec, error)
	h2          *dispatch.H2Preface
	pseudo      []string
	headers     *browser.Headers
	spelling    http1.Spelling
	maxConns    int
	idle        time.Duration
}

func newProfile(p Profile) (*profile, error) {
	h2, err := h2Preface(p.HTTP2)
	if err != nil {
		return nil, fmt.Errorf("HTTP2: %w", err)
	}
	for i, name := range p.PseudoOrder {
		if len(name) < 2 || name[0] != ':' {
			return nil, fmt.Errorf("PseudoOrder: %q is not a pseudo-header", name)
		}
		if slices.Contains(p.PseudoOrder[:i], name) {
			return nil, fmt.Errorf("PseudoOrder: %q repeated", name)
		}
	}
	headers, err := browserHeaders(p)
	if err != nil {
		return nil, err
	}
	sp, err := spelling(p.H1Spelling)
	if err != nil {
		return nil, fmt.Errorf("H1Spelling: %w", err)
	}
	if p.MaxConnsPerHost < 0 || p.IdleConnTimeout < 0 {
		return nil, errors.New("negative MaxConnsPerHost or IdleConnTimeout")
	}
	return &profile{
		clientHello: p.ClientHello,
		h2:          h2,
		pseudo:      slices.Clone(p.PseudoOrder),
		headers:     headers,
		spelling:    sp,
		maxConns:    p.MaxConnsPerHost,
		idle:        p.IdleConnTimeout,
	}, nil
}

// apply fills the parts of c that no other option set.
func (p *profile) apply(c *config) {
	if c.clientHello == nil {
		c.clientHello = p.clientHello
	}
	if c.h2 == nil {
		c.h2 = p.h2
	}
	if c.order == nil {
		c.order = &order.Order{}
	}
	if c.order.Pseudo == nil {
		c.order.Pseudo = p.pseudo
	}
	c.headers = p.headers
	if c.spelling == nil && len(p.spelling) > 0 {
		c.spelling = p.spelling
	}
	if c.maxConnsPerHost == 0 {
		c.maxConnsPerHost = p.maxConns
	}
	if c.idleConnTimeout == 0 {
		c.idleConnTimeout = p.idle
	}
}

// browserHeaders validates and copies the headers of p; nil if it adds
// none.
func browserHeaders(p Profile) (*browser.Headers, error) {
	if len(p.Headers) == 0 && len(p.InsecureHeaders) == 0 && len(p.Dests) == 0 {
		return nil, nil
	}
	h := &browser.Headers{Dests: make(map[string]browser.Dest, len(p.Dests)), H1Connection: p.H1Connection}
	for _, l := range []struct {
		name string
		in   []HeaderField
		out  *[]order.Field
	}{{"Headers", p.Headers, &h.Secure}, {"InsecureHeaders", p.InsecureHeaders, &h.Insecure}} {
		for _, f := range l.in {
			if !httpguts.ValidHeaderFieldName(f.Name) || !httpguts.ValidHeaderFieldValue(f.Value) {
				return nil, fmt.Errorf("%s: invalid field %q: %q", l.name, f.Name, f.Value)
			}
			*l.out = append(*l.out, order.Field(f))
		}
	}
	for dest, d := range p.Dests {
		if !fetch.Known(string(dest)) {
			return nil, fmt.Errorf("Dests: unknown destination %q", dest)
		}
		if d.Mode == "" {
			return nil, fmt.Errorf("Dests: %q without Mode", dest)
		}
		for _, v := range []string{d.Mode, d.Accept, d.Priority} {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, fmt.Errorf("Dests: %q: invalid value %q", dest, v)
			}
		}
		h.Dests[string(dest)] = browser.Dest{
			Mode: d.Mode, Accept: d.Accept, Priority: d.Priority,
			User: d.User, UpgradeInsecure: d.UpgradeInsecureRequests, Navigation: d.Navigation,
		}
	}
	for _, l := range []struct {
		name string
		in   []string
		out  *[]string
	}{{"NavigationOrder", p.NavigationOrder, &h.NavigationOrder}, {"SubresourceOrder", p.SubresourceOrder, &h.SubresourceOrder}} {
		for _, n := range l.in {
			if !httpguts.ValidHeaderFieldName(n) {
				return nil, fmt.Errorf("%s: invalid name %q", l.name, n)
			}
		}
		*l.out = slices.Clone(l.in)
	}
	if !httpguts.ValidHeaderFieldValue(p.H1Connection) {
		return nil, fmt.Errorf("H1Connection: invalid value %q", p.H1Connection)
	}
	return h, nil
}
