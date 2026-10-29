//go:build !unix

package http1

import "net"

// peekSocket has no socket peek outside Unix: Idle checks only what was
// already read.
func peekSocket(net.Conn) bool { return false }
