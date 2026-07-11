package browserauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func Test_Capturer_Capture_removesTemporaryProfile_whenProfileDirAbsent(t *testing.T) {
	// Given
	tempProfile := filepath.Join(t.TempDir(), "capture-profile")
	restoreProfileOS(t)
	osMkdirTemp = func(dir string, pattern string) (string, error) {
		if dir != "" {
			t.Fatalf("MkdirTemp dir = %q, want default temp root", dir)
		}
		if pattern != "gp-socks-browser-*" {
			t.Fatalf("MkdirTemp pattern = %q, want gp-socks-browser-*", pattern)
		}
		if err := os.MkdirAll(tempProfile, 0o700); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
		return tempProfile, nil
	}
	removed := ""
	osRemoveAll = func(path string) error {
		removed = path
		return os.RemoveAll(path)
	}
	runner := &recordingBrowserRunner{artifact: testCaptureArtifact(t)}
	capturer := testCapturer(runner)

	// When
	_, err := capturer.Capture(context.Background(), testCaptureRequest(t, ""))

	// Then
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	if got := runner.onlyRequest(t).profileDir; got != tempProfile {
		t.Fatalf("profile dir = %q, want temp profile %q", got, tempProfile)
	}
	if removed != tempProfile {
		t.Fatalf("removed profile dir = %q, want %q", removed, tempProfile)
	}
	if _, err := os.Stat(tempProfile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp profile still exists; Stat() error = %v", err)
	}
}

func Test_Capturer_Capture_preservesPersistentProfile_whenProfileDirSupplied(t *testing.T) {
	// Given
	profileDir := filepath.Join(t.TempDir(), "persistent-profile")
	restoreProfileOS(t)
	osMkdirTemp = func(string, string) (string, error) {
		t.Fatal("MkdirTemp() was called for persistent profile")
		return "", nil
	}
	removed := false
	osRemoveAll = func(string) error {
		removed = true
		return nil
	}
	runner := &recordingBrowserRunner{artifact: testCaptureArtifact(t)}
	capturer := testCapturer(runner)

	// When
	_, err := capturer.Capture(context.Background(), testCaptureRequest(t, profileDir))

	// Then
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	if got := runner.onlyRequest(t).profileDir; got != profileDir {
		t.Fatalf("profile dir = %q, want persistent profile %q", got, profileDir)
	}
	if removed {
		t.Fatal("persistent profile was removed")
	}
	if info, err := os.Stat(profileDir); err != nil || !info.IsDir() {
		t.Fatalf("persistent profile Stat() = (%v, %v), want directory", info, err)
	}
}

func Test_Capturer_Capture_resolvesPersistentProfileToAbsolutePath_whenProfileDirRelative(t *testing.T) {
	// Given
	workDir := t.TempDir()
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldDir); err != nil {
			t.Fatalf("restore Chdir() error = %v", err)
		}
	})
	profileDir := "persistent-profile"
	wantProfileDir, err := filepath.Abs(profileDir)
	if err != nil {
		t.Fatalf("Abs() error = %v", err)
	}
	restoreProfileOS(t)
	runner := &recordingBrowserRunner{artifact: testCaptureArtifact(t)}
	capturer := testCapturer(runner)

	// When
	_, err = capturer.Capture(context.Background(), testCaptureRequest(t, profileDir))

	// Then
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	if got := runner.onlyRequest(t).profileDir; got != wantProfileDir {
		t.Fatalf("profile dir = %q, want absolute path %q", got, wantProfileDir)
	}
	if info, err := os.Stat(wantProfileDir); err != nil || !info.IsDir() {
		t.Fatalf("persistent profile Stat() = (%v, %v), want directory", info, err)
	}
}

func Test_Capturer_Capture_reusesPersistentProfile_whenSameProfileDirSuppliedTwice(t *testing.T) {
	// Given
	profileDir := filepath.Join(t.TempDir(), "persistent-profile")
	restoreProfileOS(t)
	osMkdirTemp = func(string, string) (string, error) {
		t.Fatal("MkdirTemp() was called for persistent profile")
		return "", nil
	}
	runner := &recordingBrowserRunner{artifact: testCaptureArtifact(t)}
	capturer := testCapturer(runner)
	request := testCaptureRequest(t, profileDir)

	// When
	_, firstErr := capturer.Capture(context.Background(), request)
	_, secondErr := capturer.Capture(context.Background(), request)

	// Then
	if firstErr != nil {
		t.Fatalf("first Capture() error = %v", firstErr)
	}
	if secondErr != nil {
		t.Fatalf("second Capture() error = %v", secondErr)
	}
	if len(runner.requests) != 2 {
		t.Fatalf("capture runs = %d, want 2", len(runner.requests))
	}
	for index, request := range runner.requests {
		if request.profileDir != profileDir {
			t.Fatalf("capture %d profile dir = %q, want %q", index+1, request.profileDir, profileDir)
		}
	}
}

func Test_Capturer_Capture_createsPersistentProfileOwnerOnly_whenModeChecksSupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows mode bits do not express owner-only directory access")
	}
	// Given
	profileDir := filepath.Join(t.TempDir(), "persistent-profile")
	restoreProfileOS(t)
	runner := &recordingBrowserRunner{artifact: testCaptureArtifact(t)}
	capturer := testCapturer(runner)

	// When
	_, err := capturer.Capture(context.Background(), testCaptureRequest(t, profileDir))

	// Then
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	info, err := os.Stat(profileDir)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("profile permissions = %o, want 700", got)
	}
}

func Test_Capturer_Capture_usesTempProfileNotDefaultBrowserStore_whenProfileDirAbsent(t *testing.T) {
	// Given
	tempProfile := filepath.Join(t.TempDir(), "capture-profile")
	defaultRoot := t.TempDir()
	t.Setenv("HOME", filepath.Join(defaultRoot, "home"))
	t.Setenv("LOCALAPPDATA", filepath.Join(defaultRoot, "local-app-data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(defaultRoot, "xdg-config"))
	restoreProfileOS(t)
	osMkdirTemp = func(string, string) (string, error) {
		return tempProfile, os.MkdirAll(tempProfile, 0o700)
	}
	runner := &recordingBrowserRunner{artifact: testCaptureArtifact(t)}
	capturer := testCapturer(runner)

	// When
	_, err := capturer.Capture(context.Background(), testCaptureRequest(t, ""))

	// Then
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	got := runner.onlyRequest(t).profileDir
	if got != tempProfile {
		t.Fatalf("profile dir = %q, want temp profile %q", got, tempProfile)
	}
	for _, forbidden := range defaultBrowserProfileRoots(defaultRoot) {
		if strings.HasPrefix(got, forbidden) {
			t.Fatalf("profile dir = %q, used default browser profile root %q", got, forbidden)
		}
	}
}

func restoreProfileOS(t *testing.T) {
	t.Helper()
	oldMkdirTemp := osMkdirTemp
	oldRemoveAll := osRemoveAll
	t.Cleanup(func() {
		osMkdirTemp = oldMkdirTemp
		osRemoveAll = oldRemoveAll
	})
}
