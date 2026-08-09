package browserauth

import "sync"

// ProfileSession owns a browser profile for the lifetime of an authentication
// flow. An empty profileDir creates an isolated temporary profile; a non-empty
// profileDir keeps the existing persistent-profile behavior.
type ProfileSession struct {
	profile   captureProfile
	closeOnce sync.Once
	closeErr  error
}

// NewProfileSession prepares one browser profile that can be supplied to more
// than one Capture call. The caller must call Close after all captures finish.
func NewProfileSession(profileDir string) (*ProfileSession, error) {
	profile, err := captureProfileDir(profileDir)
	if err != nil {
		return nil, err
	}
	return &ProfileSession{profile: profile}, nil
}

// ProfileDir returns the actual user-data directory for Capture requests.
func (s *ProfileSession) ProfileDir() string {
	return s.profile.dir
}

// Close removes an isolated temporary profile. Persistent profiles are kept.
// Close is idempotent.
func (s *ProfileSession) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.profile.cleanup()
	})
	return s.closeErr
}
