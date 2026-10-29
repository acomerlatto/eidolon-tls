package http2

import (
	"errors"
	"fmt"
)

// CheckSettings validates the SETTINGS of Transport.Settings and the
// ConnWindowUpdate sent with them: no setting twice, values allowed by RFC
// 9113 section 6.5.2, ENABLE_PUSH present and 0, since the client refuses
// server push and the initial value is 1, a stream window and a header
// list limit above zero, and a connection window within 2^31-1.
func CheckSettings(settings []Setting, connWindowUpdate uint32) error {
	seen := make(map[SettingID]bool, len(settings))
	for _, s := range settings {
		if seen[s.ID] {
			return fmt.Errorf("http2: setting %v repeated", s.ID)
		}
		seen[s.ID] = true
		if err := s.Valid(); err != nil {
			return fmt.Errorf("http2: invalid %v: %w", s, err)
		}
		switch s.ID {
		case SettingEnablePush:
			if s.Val != 0 {
				return errors.New("http2: ENABLE_PUSH must be 0: server push is refused")
			}
		case SettingInitialWindowSize, SettingMaxHeaderListSize:
			if s.Val == 0 {
				return fmt.Errorf("http2: %v must be above 0", s.ID)
			}
		case SettingNoRFC7540Priorities:
			if s.Val > 1 {
				return fmt.Errorf("http2: invalid %v", s)
			}
		}
	}
	if !seen[SettingEnablePush] {
		return errors.New("http2: no ENABLE_PUSH: its initial value 1 allows server push, which is refused")
	}
	if connWindowUpdate > 1<<31-1-initialWindowSize {
		return fmt.Errorf("http2: connection window update %d above 2^31-1-%d", connWindowUpdate, initialWindowSize)
	}
	return nil
}

// PriorityFrameParam is a PRIORITY frame of Transport.PriorityFrames.
type PriorityFrameParam struct {
	StreamID uint32
	PriorityParam
}

// maxStreamIDValue is the largest stream ID (RFC 9113 section 5.1.1).
const maxStreamIDValue = 1<<31 - 1

// CheckPriorities validates the PRIORITY frames, the HEADERS priority and
// the first stream of Transport.PriorityFrames, HeaderPriority and
// FirstStreamID: stream IDs within 2^31-1, a PRIORITY frame neither on
// stream 0 nor depending on its own stream, and an odd first stream.
func CheckPriorities(frames []PriorityFrameParam, header *PriorityParam, first uint32) error {
	for _, f := range frames {
		switch {
		case f.StreamID == 0 || f.StreamID > maxStreamIDValue:
			return fmt.Errorf("http2: PRIORITY frame on stream %d", f.StreamID)
		case f.StreamDep > maxStreamIDValue:
			return fmt.Errorf("http2: PRIORITY frame depending on stream %d", f.StreamDep)
		case f.StreamDep == f.StreamID:
			return fmt.Errorf("http2: PRIORITY frame on stream %d depending on itself", f.StreamID)
		}
	}
	if header != nil && header.StreamDep > maxStreamIDValue {
		return fmt.Errorf("http2: HEADERS priority depending on stream %d", header.StreamDep)
	}
	if first != 0 && (first%2 == 0 || first > maxStreamIDValue) {
		return fmt.Errorf("http2: first stream %d is not an odd stream ID", first)
	}
	return nil
}
