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

	utls "github.com/acomerlatto/utls"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
)

// HttpClient sends requests with the configured browser fingerprint.
type HttpClient interface {
	// Do sends a request, as http.Client.Do.
	Do(req *http.Request) (*http.Response, error)
	// Get, Head and Post are the http.Client shortcuts.
	Get(url string) (*http.Response, error)
	Head(url string) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)

	// CloseIdleConnections closes connections that carry no request. It
	// never interrupts a response in progress.
	CloseIdleConnections()
	// Close stops the client: new requests fail with ErrClosed and every
	// connection is closed, including responses still being read.
	Close() error

	// Transport returns the RoundTripper used by the client, for code that
	// builds its own http.Client. It shares connections with the client.
	// WithTimeout is not part of it: the http.Client that uses it sets
	// its own timeout.
	Transport() http.RoundTripper
}

// New returns a client configured by opts. WithClientHello is required.
// Invalid or missing options return an error that wraps ErrConfig.
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
		Protocols:   alpn,
	}
	return &client{
		hc: &http.Client{Transport: tr, Timeout: cfg.timeout},
		tr: tr,
	}, nil
}

type client struct {
	hc *http.Client
	tr *dispatch.Transport
}

func (c *client) Do(req *http.Request) (*http.Response, error) { return c.hc.Do(req) }
func (c *client) Get(url string) (*http.Response, error)       { return c.hc.Get(url) }
func (c *client) Head(url string) (*http.Response, error)      { return c.hc.Head(url) }

func (c *client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.hc.Post(url, contentType, body)
}

func (c *client) CloseIdleConnections()        { c.hc.CloseIdleConnections() }
func (c *client) Close() error                 { return c.tr.Close() }
func (c *client) Transport() http.RoundTripper { return c.tr }
