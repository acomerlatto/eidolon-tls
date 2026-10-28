package http2

import (
	"errors"
	"fmt"
)

// CheckSettings validates the SETTINGS of Transport.Settings and the
// ConnWindowUpdate sent with them: no setting twice, values allowed by RFC
// 9113 section 6.5.2, ENABLE_PUSH never 1, since the client refuses server
// push, a stream window and a header list limit above zero, and a
// connection window within 2^31-1.
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
	if connWindowUpdate > 1<<31-1-initialWindowSize {
		return fmt.Errorf("http2: connection window update %d above 2^31-1-%d", connWindowUpdate, initialWindowSize)
	}
	return nil
}
