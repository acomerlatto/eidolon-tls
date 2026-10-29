// The places a raised MAX_CONCURRENT_STREAMS opens (patch 0038).

package http2

import (
	"slices"
	"testing"
	"testing/synctest"
)

// A request waiting for a place in strict mode takes the one a SETTINGS
// frame raising MAX_CONCURRENT_STREAMS opens, as Chromium's
// ProcessPendingStreamRequests, without waiting for a stream to end.
func TestMaxConcurrentStreamsRaised(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newErrorServerStart(t, &Transport{StrictMaxConcurrentStreams: true}, func(fr *Framer) {
			fr.WriteSettings(Setting{SettingMaxConcurrentStreams, 1})
		})
		s.request(false) // stream 1 holds the only place
		s.request(false) // waits
		s.fr.WriteSettings(Setting{SettingMaxConcurrentStreams, 2})
		synctest.Wait()
		if got, want := s.frames(), []string{"SETTINGS ACK", "HEADERS 3"}; !slices.Equal(got, want) {
			t.Fatalf("frames %q, want %q", got, want)
		}
	})
}
