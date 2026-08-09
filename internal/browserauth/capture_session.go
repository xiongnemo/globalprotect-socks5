package browserauth

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

var (
	ErrCaptureSessionClosed = errors.New("browserauth: capture session closed")
	ErrCaptureConfigChanged = errors.New("browserauth: capture session configuration changed")
)

// CaptureSession keeps one isolated browser runtime alive across all SAML
// captures in an authentication flow. Captures are serialized.
type CaptureSession struct {
	capturer Capturer
	lifetime context.Context

	mu       sync.Mutex
	config   captureSessionConfig
	profile  *ProfileSession
	runtime  browserRuntime
	started  bool
	closed   bool
	closeErr error
}

type captureSessionConfig struct {
	browser     Browser
	browserPath string
	profileDir  string
}

// NewCaptureSession creates a lazy session. The browser starts on the first
// Capture and remains alive until Close.
func (c Capturer) NewCaptureSession(ctx context.Context) *CaptureSession {
	return &CaptureSession{capturer: c, lifetime: ctx}
}

func (s *CaptureSession) Capture(ctx context.Context, request Request) (gp.AuthArtifact, error) {
	if err := validateCapturePrelogin(request.Prelogin); err != nil {
		return gp.AuthArtifact{}, err
	}
	if err := ctx.Err(); err != nil {
		return gp.AuthArtifact{}, fmt.Errorf("capture browser auth: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return gp.AuthArtifact{}, ErrCaptureSessionClosed
	}
	if err := s.lifetime.Err(); err != nil {
		return gp.AuthArtifact{}, fmt.Errorf("browser auth session: %w", err)
	}
	config, err := normalizedCaptureConfig(request)
	if err != nil {
		return gp.AuthArtifact{}, err
	}
	if !s.started {
		if err := s.start(config); err != nil {
			return gp.AuthArtifact{}, err
		}
	} else if config != s.config {
		return gp.AuthArtifact{}, ErrCaptureConfigChanged
	}
	target, err := navigationURL(request.Prelogin, s.profile.ProfileDir())
	if err != nil {
		return gp.AuthArtifact{}, err
	}
	return s.runtime.capture(ctx, runtimeCaptureRequest{target: target, timeout: request.Timeout})
}

func (s *CaptureSession) start(config captureSessionConfig) error {
	browserPath, err := s.capturer.finder.find(config.browser, config.browserPath)
	if err != nil {
		return err
	}
	profile, err := NewProfileSession(config.profileDir)
	if err != nil {
		return err
	}
	factory := s.capturer.runtimeFactory
	if factory == nil {
		factory = runnerRuntimeFactory(s.capturer.runner)
	}
	runtime, err := factory(s.lifetime, browserRuntimeConfig{
		browserPath: browserPath, profileDir: profile.ProfileDir(),
	})
	if err != nil {
		return errors.Join(err, closeUnusedProfile(profile))
	}
	s.config, s.profile, s.runtime, s.started = config, profile, runtime, true
	return nil
}

func (s *CaptureSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	var runtimeErr, profileErr error
	if s.runtime != nil {
		runtimeErr = s.runtime.close()
	}
	if s.profile != nil {
		profileErr = s.profile.Close()
	}
	s.closeErr = errors.Join(
		wrapCloseError("browser runtime", runtimeErr),
		wrapCloseError("browser profile", profileErr),
	)
	return s.closeErr
}

func normalizedCaptureConfig(request Request) (captureSessionConfig, error) {
	browser := request.Browser
	if browser == "" {
		browser = BrowserAuto
	}
	profileDir := strings.TrimSpace(request.ProfileDir)
	if profileDir != "" {
		absolute, err := filepath.Abs(profileDir)
		if err != nil {
			return captureSessionConfig{}, fmt.Errorf("resolve browser profile: %w", err)
		}
		profileDir = absolute
	}
	return captureSessionConfig{
		browser: browser, browserPath: strings.TrimSpace(request.BrowserPath), profileDir: profileDir,
	}, nil
}

func validateCapturePrelogin(prelogin gp.Prelogin) error {
	if prelogin.AuthMode != gp.AuthModeSAML || prelogin.SAMLRequest.String() == "" {
		return fmt.Errorf("browser auth prelogin: %w", gp.ErrInvalidPrelogin)
	}
	return nil
}

func closeUnusedProfile(profile *ProfileSession) error {
	if err := profile.Close(); err != nil {
		return fmt.Errorf("close browser profile after start failure: %w", err)
	}
	return nil
}

func wrapCloseError(subject string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close %s: %w", subject, err)
}
