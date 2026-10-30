package dispatch_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/acomerlatto/eidolon-tls/internal/http2"
	"github.com/acomerlatto/eidolon-tls/internal/lab"
)

// With NewConnPerRequest, a request that goes again on a new connection,
// here over HTTP/1.1 after HTTP_1_1_REQUIRED, does not resume the session
// of its first connection.
func TestNoResumptionAlone(t *testing.T) {
	srv := lab.Start(t, lab.Options{
		H2Conn: rawH2(func(fr *http2.Framer, stream uint32, n int) bool {
			fr.WriteRSTStream(stream, http2.ErrCodeHTTP11Required)
			return false
		}),
	})
	tr := transport(srv)
	tr.NewConnPerRequest = true
	defer tr.Close()
	resp, err := (&http.Client{Transport: tr}).Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	srv.NextConn(t)
	if c := srv.NextConn(t); c.State.DidResume {
		t.Error("the second connection of the request resumed")
	}
}
