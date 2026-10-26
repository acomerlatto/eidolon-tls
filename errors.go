package eidolon

import (
	"errors"

	"github.com/acomerlatto/eidolon-tls/internal/dispatch"
	"github.com/acomerlatto/eidolon-tls/internal/tlsdial"
)

// Errors returned by the client, wrapped with context. Test them with
// errors.Is; http.Client wraps transport errors in *url.Error, which
// unwraps to them.
var (
	// ErrConfig reports an invalid option or a missing required one.
	ErrConfig = errors.New("eidolon: invalid configuration")
	// ErrClosed reports a request on a closed client.
	ErrClosed = dispatch.ErrClosed
	// ErrALPN reports a protocol negotiated by ALPN that no engine handles.
	ErrALPN = tlsdial.ErrALPN
)
