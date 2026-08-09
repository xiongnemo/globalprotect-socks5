package browserauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_ProfileSession_reusesOneTemporaryProfileUntilClose(t *testing.T) {
	tempProfile := filepath.Join(t.TempDir(), "capture-profile")
	restoreProfileOS(t)
	mkdirCalls := 0
	osMkdirTemp = func(string, string) (string, error) {
		mkdirCalls++
		return tempProfile, os.MkdirAll(tempProfile, 0o700)
	}
	removeCalls := 0
	osRemoveAll = func(path string) error {
		removeCalls++
		return os.RemoveAll(path)
	}
	runner := &recordingBrowserRunner{artifact: testCaptureArtifact(t)}
	capturer := testCapturer(runner)

	session, err := NewProfileSession("")
	if err != nil {
		t.Fatalf("NewProfileSession() error = %v", err)
	}
	request := testCaptureRequest(t, session.ProfileDir())
	if _, err := capturer.Capture(context.Background(), request); err != nil {
		t.Fatalf("first Capture() error = %v", err)
	}
	if _, err := capturer.Capture(context.Background(), request); err != nil {
		t.Fatalf("second Capture() error = %v", err)
	}
	if mkdirCalls != 1 {
		t.Fatalf("MkdirTemp() calls = %d, want 1", mkdirCalls)
	}
	if removeCalls != 0 {
		t.Fatalf("RemoveAll() calls before Close = %d, want 0", removeCalls)
	}
	assertSharedProfile(t, runner.requests, tempProfile)

	if err := session.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if removeCalls != 1 {
		t.Fatalf("RemoveAll() calls = %d, want 1", removeCalls)
	}
	if _, err := os.Stat(tempProfile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary profile still exists; Stat() error = %v", err)
	}
}

func Test_ProfileSession_usesIsolatedTemporaryProfile(t *testing.T) {
	tempProfile := filepath.Join(t.TempDir(), "capture-profile")
	defaultRoot := t.TempDir()
	t.Setenv("HOME", filepath.Join(defaultRoot, "home"))
	t.Setenv("LOCALAPPDATA", filepath.Join(defaultRoot, "local-app-data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(defaultRoot, "xdg-config"))
	restoreProfileOS(t)
	osMkdirTemp = func(string, string) (string, error) {
		return tempProfile, os.MkdirAll(tempProfile, 0o700)
	}

	session, err := NewProfileSession("")
	if err != nil {
		t.Fatalf("NewProfileSession() error = %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	for _, forbidden := range defaultBrowserProfileRoots(defaultRoot) {
		if strings.HasPrefix(session.ProfileDir(), forbidden) {
			t.Fatalf("profile dir = %q, used browser profile root %q", session.ProfileDir(), forbidden)
		}
	}
}

func Test_ProfileSession_preservesPersistentProfile(t *testing.T) {
	profileDir := filepath.Join(t.TempDir(), "persistent-profile")
	restoreProfileOS(t)
	osMkdirTemp = func(string, string) (string, error) {
		t.Fatal("MkdirTemp() was called for a persistent profile")
		return "", nil
	}
	removed := false
	osRemoveAll = func(string) error {
		removed = true
		return nil
	}

	session, err := NewProfileSession(profileDir)
	if err != nil {
		t.Fatalf("NewProfileSession() error = %v", err)
	}
	if session.ProfileDir() != profileDir {
		t.Fatalf("ProfileDir() = %q, want %q", session.ProfileDir(), profileDir)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if removed {
		t.Fatal("persistent profile was removed")
	}
	if info, err := os.Stat(profileDir); err != nil || !info.IsDir() {
		t.Fatalf("persistent profile Stat() = (%v, %v), want directory", info, err)
	}
}

func Test_ProfileSession_closeCleansAfterCaptureFailureOrCancellation(t *testing.T) {
	tests := []struct {
		name       string
		captureErr func(context.Context) error
	}{
		{name: "runner error", captureErr: func(context.Context) error { return errors.New("capture failed") }},
		{name: "canceled context", captureErr: func(ctx context.Context) error { return ctx.Err() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profileDir := filepath.Join(t.TempDir(), "capture-profile")
			restoreProfileOS(t)
			osMkdirTemp = func(string, string) (string, error) {
				return profileDir, os.MkdirAll(profileDir, 0o700)
			}
			capturer := testCapturerWithError(test.captureErr)
			ctx, cancel := context.WithCancel(context.Background())
			if test.name == "canceled context" {
				cancel()
			} else {
				defer cancel()
			}

			err := captureInProfileSession(ctx, capturer, testCaptureRequest(t, ""))
			if err == nil {
				t.Fatal("captureInProfileSession() error = nil, want error")
			}
			if _, statErr := os.Stat(profileDir); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("temporary profile still exists; Stat() error = %v", statErr)
			}
		})
	}
}

func captureInProfileSession(ctx context.Context, capturer Capturer, request Request) (err error) {
	session, err := NewProfileSession(request.ProfileDir)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	request.ProfileDir = session.ProfileDir()
	_, err = capturer.Capture(ctx, request)
	return err
}

func testCapturerWithError(captureErr func(context.Context) error) Capturer {
	capturer := testCapturer(&recordingBrowserRunner{})
	capturer.runner = func(ctx context.Context, _ browserRunRequest) (gp.AuthArtifact, error) {
		return gp.AuthArtifact{}, captureErr(ctx)
	}
	return capturer
}

func assertSharedProfile(t *testing.T, requests []browserRunRequest, want string) {
	t.Helper()
	if len(requests) != 2 {
		t.Fatalf("capture runs = %d, want 2", len(requests))
	}
	for index, request := range requests {
		if request.profileDir != want {
			t.Fatalf("capture %d profile dir = %q, want %q", index+1, request.profileDir, want)
		}
	}
}
