// Package eidolon is an HTTP client for Go that reproduces the connections of
// real browsers: TLS ClientHello, HTTP/2 frames and settings, and header
// order and spelling in HTTP/2 and HTTP/1.1.
//
// The API uses the standard net/http types. New returns an HttpClient; its
// Transport also works inside any http.Client.
//
// Response.TLS is converted from the uTLS connection state. Its
// ExportKeyingMaterial cannot reach the connection and panics if called.
package eidolon

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
)

// HttpClient sends requests with the configured browser fingerprint.
type HttpClient interface {
	// Do sends a request, as http.Client.Do. Redirects are followed as
	// the Fetch standard and Chrome do: up to 20, then ErrTooManyRedirects;
	// 301 and 302 turn only a POST into a GET, 303 anything but GET and
	// HEAD, and the other cases send the method and body again (GetBody).
	// A body without GetBody stops at the redirect, which is returned.
	//
	// Request.Close ends the connection after the request without sending
	// "Connection: close", which Chrome never sends: HTTP/1.1 closes it
	// once the response was read, HTTP/2 takes no new streams on it and
	// closes it when its streams end. A Connection field set by the caller
	// is sent on HTTP/1.1 and has the same effect, in exact mode
	// (WithExactHeaders) when it is among the fields sent.
	Do(req *http.Request) (*http.Response, error)
	// Get, Head and Post are the http.Client shortcuts.
	Get(url string) (*http.Response, error)
	Head(url string) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)

	// GetCookies returns the cookies of the jar (WithCookieJar) for u, and
	// SetCookies stores cookies in it as if u had sent them. Without a jar
	// GetCookies returns nil and SetCookies does nothing.
	GetCookies(u *url.URL) []*http.Cookie
	SetCookies(u *url.URL, cookies []*http.Cookie)

	// CloseIdleConnections closes connections that carry no request. It
	// never interrupts a response in progress.
	CloseIdleConnections()
	// Close stops the client: new requests fail with ErrClosed and every
	// connection is closed, including responses still being read.
	Close() error

	// Transport returns the RoundTripper used by the client, for code that
	// builds its own http.Client. It shares connections with the client.
	// WithTimeout is not part of it: the http.Client that uses it sets
	// its own timeout. That http.Client follows redirects by its own
	// rules: at most 10, and PUT, DELETE and PATCH turned into GET at 301
	// and 302. The transport still sets the Referer and drops the
	// credentials at each hop as the client does, cookies included: those
	// of the first request leave the chain once it changes origin. With a
	// jar in that http.Client, a cookie of the jar the first request also
	// sent leaves it too; the client's own redirects keep it.
	Transport() http.RoundTripper
}

// New returns a client configured by opts. WithClientHello is required.
// Invalid or missing options return an error that wraps ErrConfig. New
// calls the ClientHello function once and applies the spec without
// connecting: a profile that cannot be used also wraps ErrProfile.
func New(opts ...Option) (HttpClient, error) {
	var cfg config
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option", ErrConfig)
		}
		if err := opt(&cfg); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConfig, err)
		}
	}
	if cfg.profile != nil {
		cfg.profile.apply(&cfg)
	}
	if cfg.clientHello == nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, errors.New("WithClientHello is required"))
	}
	alpn, err := cfg.alpn()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	tr := &dispatch.Transport{
		Spec:        cfg.clientHello,
		TLS:         &utls.Config{RootCAs: cfg.rootCAs},
		DialContext: cfg.dialContext,
		Proxy:       cfg.proxyWithUserAgent(),
		Spelling:    cfg.spelling,
		Order:       cfg.order,
		Headers:     cfg.headers,
		Protocols:   alpn,
		H2:          cfg.h2,

		MaxConnsPerHost:   cfg.maxConnsPerHost,
		IdleConnTimeout:   cfg.idleConnTimeout,
		NewConnPerRequest: cfg.newConnPerRequest,

		DisableDecompression: cfg.disableDecompression,
		StrictTLS12:          cfg.strictTLS12,
	}
	// A profile that cannot be applied fails here, not at the first
	// request.
	if err := tr.CheckSpec(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	if err := cfg.configureECH(tr); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	doh, err := cfg.configureDoH(tr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	return &client{
		// http.Client sends one hop at a time; the client follows the
		// redirects (redirect.go) and sets the deadline.
		hc: &http.Client{
			Transport:     tr,
			Jar:           cfg.jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		tr:      tr,
		doh:     doh,
		timeout: cfg.timeout,
	}, nil
}

type client struct {
	hc      *http.Client
	tr      *dispatch.Transport
	doh     *dispatch.Transport // of WithDoH; nil without it
	timeout time.Duration
}

func (c *client) Do(req *http.Request) (*http.Response, error) {
	if c.timeout > 0 {
		return c.withTimeout(req, c.timeout)
	}
	return c.do(req)
}

func (c *client) Get(url string) (*http.Response, error) {
	return c.send(http.MethodGet, url, "", nil)
}

func (c *client) Head(url string) (*http.Response, error) {
	return c.send(http.MethodHead, url, "", nil)
}

func (c *client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.send(http.MethodPost, url, contentType, body)
}

func (c *client) send(method, url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.Do(req)
}

func (c *client) GetCookies(u *url.URL) []*http.Cookie {
	if c.hc.Jar == nil {
		return nil
	}
	return c.hc.Jar.Cookies(u)
}

func (c *client) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if c.hc.Jar != nil {
		c.hc.Jar.SetCookies(u, cookies)
	}
}

func (c *client) CloseIdleConnections() {
	c.hc.CloseIdleConnections()
	if c.doh != nil {
		c.doh.CloseIdleConnections()
	}
}

func (c *client) Close() error {
	if c.doh != nil {
		c.doh.Close()
	}
	return c.tr.Close()
}

func (c *client) Transport() http.RoundTripper { return c.tr }
