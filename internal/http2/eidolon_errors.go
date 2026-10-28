// Errors of the engine that the dispatcher reports with its own.

package http2

import "errors"

// errHeaderListTooLarge is the detail of the connection error of a header
// block that goes on in CONTINUATION frames after exceeding the limit.
var errHeaderListTooLarge = errors.New("http2: header list too large")

// ErrHeaderListSize reports a response whose header list exceeds
// MaxHeaderListSize: the cause of its StreamError, or in the chain of the
// connection error when the excess takes the connection down
// (ClientConn.readLoop).
var ErrHeaderListSize = errResponseHeaderListSize
