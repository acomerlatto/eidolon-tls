// RST_STREAM without PING (patch 0025).

package http2

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"testing"
	"testing/synctest"
)

// A request cancelled before anything is read on the connection sends its
// RST_STREAM alone with CancelWithoutPing, and the next request takes its
// place at once; without it, a PING goes with the RST_STREAM, and the
// stream holds the only place until the PING is answered.
func TestCancelWithoutPing(t *testing.T) {
	for _, tt := range []struct {
		quiet bool
		want  []string
	}{
		{true, []string{"HEADERS 1", "RST_STREAM 1 CANCEL", "HEADERS 3"}},
		{false, []string{"HEADERS 1", "RST_STREAM 1 CANCEL", "PING 0"}},
	} {
		t.Run(fmt.Sprint(tt.quiet), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, server := net.Pipe()
				seen := wireServer(server, wireOptions{silent: true, settings: []Setting{{ID: SettingMaxConcurrentStreams, Val: 1}}})
				tr := &Transport{CancelWithoutPing: tt.quiet, StrictMaxConcurrentStreams: true}
				cc, err := tr.newClientConn(client, false, nil)
				if err != nil {
					t.Fatal(err)
				}
				synctest.Wait() // the server SETTINGS are read
				send := func(ctx context.Context) <-chan error {
					req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
					done := make(chan error, 1)
					go func() {
						_, err := cc.RoundTrip(req)
						done <- err
					}()
					synctest.Wait()
					return done
				}
				ctx, cancel := context.WithCancel(context.Background())
				first := send(ctx)
				cancel()
				<-first
				second := send(context.Background())
				synctest.Wait()
				client.Close()
				<-second
				var got []string
				for f := range seen {
					switch f.typ {
					case FrameHeaders:
						got = append(got, fmt.Sprint("HEADERS ", f.stream))
					case FrameRSTStream:
						got = append(got, fmt.Sprint("RST_STREAM ", f.stream, " ", f.code))
					case FramePing:
						got = append(got, fmt.Sprint("PING ", f.stream))
					}
				}
				if !slices.Equal(got, tt.want) {
					t.Errorf("frames %v, want %v", got, tt.want)
				}
			})
		})
	}
}
