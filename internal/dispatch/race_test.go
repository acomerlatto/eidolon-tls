//go:build race

package dispatch

// raceEnabled: sync.Pool drops a share of Put calls under the race detector.
const raceEnabled = true
