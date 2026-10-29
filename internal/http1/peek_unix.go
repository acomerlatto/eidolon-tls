//go:build unix

package http1

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// peekSocket reports whether the socket under c, below TLS and the
// connections that unwrap with NetConn, has bytes or the end of the stream
// waiting, without reading them or waiting, as Chromium's
// TCPSocket::IsConnectedAndIdle does with MSG_PEEK. A c without a socket
// has none.
func peekSocket(c net.Conn) (pending bool) {
	for {
		nc, wraps := c.(interface{ NetConn() net.Conn })
		if !wraps {
			break
		}
		c = nc.NetConn()
	}
	sc, isSocket := c.(syscall.Conn)
	if !isSocket {
		return false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	var buf [1]byte
	rc.Read(func(fd uintptr) bool {
		n, _, err := unix.Recvfrom(int(fd), buf[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		// n == 0 without error is the end of the stream.
		pending = err != unix.EAGAIN && err != unix.EWOULDBLOCK || n > 0
		return true
	})
	return pending
}
