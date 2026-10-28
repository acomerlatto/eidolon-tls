package http1

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
)

// An empty Read of a probed body keeps the probed byte for the next one.
func TestProbedBodyEmptyRead(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", nil)
	req.Body = io.NopCloser(strings.NewReader("abc"))
	req, err := probeBody(req)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := req.Body.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty Read = %d, %v", n, err)
	}
	if got, err := io.ReadAll(req.Body); string(got) != "abc" || err != nil {
		t.Fatalf("got %q, %v", got, err)
	}
}

// reset takes ECONNRESET and EPIPE, wrapped as net.Conn reports them, as
// Chrome's ERR_CONNECTION_RESET.
func TestReset(t *testing.T) {
	wrap := func(errno error) error {
		return &net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", errno)}
	}
	for err, want := range map[error]bool{
		wrap(syscall.ECONNRESET):                   true,
		wrap(syscall.EPIPE):                        true,
		fmt.Errorf("tls: %w", wrap(syscall.EPIPE)): true,
		wrap(syscall.ECONNREFUSED):                 false,
		io.EOF:                                     false,
	} {
		if got := reset(err); got != want {
			t.Errorf("reset(%v) = %v", err, got)
		}
	}
}
