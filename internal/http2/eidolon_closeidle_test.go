// A connection closed when it loses its last stream (patch 0045).

package http2

import (
	"testing"
	"testing/synctest"
)

// With CloseIdleIf true, a connection closes when its last stream ends,
// as Chromium's SpdySession when its socket pool is stalled; with false,
// it stays.
func TestCloseIdleIf(t *testing.T) {
	for _, stalled := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			s := newErrorServer(t, &Transport{CloseIdleIf: func() bool { return stalled }})
			done := s.request(true)
			s.raw(FrameHeaders, FlagHeadersEndHeaders|FlagHeadersEndStream, 1, status200...)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			if got := s.cc.State().Closed; got != stalled {
				t.Errorf("CloseIdleIf %v: closed %v", stalled, got)
			}
		})
	}
}
