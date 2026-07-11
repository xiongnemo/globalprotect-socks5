package browserauth

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

type captureProfile struct {
	dir           string
	removeOnClose bool
}

func captureProfileDir(raw string) (captureProfile, error) {
	dir := strings.TrimSpace(raw)
	if dir == "" {
		profileDir, err := osMkdirTemp("", "gp-socks-browser-*")
		if err != nil {
			return captureProfile{}, fmt.Errorf("create browser profile: %w", err)
		}
		return captureProfile{dir: profileDir, removeOnClose: true}, nil
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return captureProfile{}, fmt.Errorf("resolve persistent browser profile: %w", err)
	}
	dir = absDir
	if err := osMkdirAll(dir, 0o700); err != nil {
		return captureProfile{}, fmt.Errorf("create persistent browser profile: %w", err)
	}
	if supportsOwnerOnlyModes() {
		if err := osChmod(dir, 0o700); err != nil {
			return captureProfile{}, fmt.Errorf("secure persistent browser profile: %w", err)
		}
	}
	return captureProfile{dir: dir}, nil
}

func (p captureProfile) cleanup() error {
	if p.removeOnClose {
		if err := osRemoveAll(p.dir); err != nil {
			return fmt.Errorf("remove browser profile: %w", err)
		}
	}
	return nil
}

func supportsOwnerOnlyModes() bool {
	return runtime.GOOS != "windows"
}
