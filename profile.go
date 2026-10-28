package eidolon

import (
	"errors"
	"fmt"
	"slices"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
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
	// H1Spelling spells header names over HTTP/1.1, as
	// WithHeaderSpelling; names not listed are sent in canonical form.
	H1Spelling []string
	// MaxConnsPerHost and IdleConnTimeout are those of WithMaxConnsPerHost
	// and WithIdleConnTimeout; zero keeps the default.
	MaxConnsPerHost int
	IdleConnTimeout time.Duration
}

// Chrome156Linux returns the profile of Chrome 156.0.8078.73 on Linux, as
// captured on 28/10/2026: the ClientHello of the uTLS fork's
// HelloChrome_155, whose extensions are shuffled on each connection, the
// HTTP/2 SETTINGS, WINDOW_UPDATE and priority of Chrome, the pseudo-header
// order :method, :authority, :scheme, :path, the client hints in lowercase
// over HTTP/1.1, and 6 connections per host. Each call returns a new copy.
func Chrome156Linux() Profile {
	return Profile{
		Name: "chrome/156/linux",
		ClientHello: func() (*utls.ClientHelloSpec, error) {
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
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
		},
		PseudoOrder:     []string{":method", ":authority", ":scheme", ":path"},
		H1Spelling:      []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"},
		MaxConnsPerHost: dispatch.DefaultMaxConnsPerHost,
		IdleConnTimeout: dispatch.DefaultIdleConnTimeout,
	}
}

// WithProfile sets the profile of the client. The options that set one of
// its parts, such as WithClientHello or WithHTTP2Settings, take precedence
// over that part, whatever their position. A profile that cannot be used
// returns an error that wraps ErrConfig: invalid HTTP2 (see
// WithHTTP2Settings), a pseudo-header order with a name repeated or not a
// pseudo-header, an invalid spelling (see WithHeaderSpelling), or a
// negative MaxConnsPerHost or IdleConnTimeout. The profile is copied when
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
