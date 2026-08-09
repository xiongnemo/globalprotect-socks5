package browserauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_CaptureSession_reusesRuntimeAndClosesItBeforeTemporaryProfile(t *testing.T) {
	profileDir := filepath.Join(t.TempDir(), "capture-profile")
	restoreProfileOS(t)
	osMkdirTemp = func(string, string) (string, error) {
		return profileDir, os.MkdirAll(profileDir, 0o700)
	}
	order := []string{}
	osRemoveAll = func(path string) error {
		order = append(order, "profile")
		return os.RemoveAll(path)
	}
	runtime := &recordingRuntime{
		artifact: testCaptureArtifact(t),
		closeFunc: func() error {
			order = append(order, "runtime")
			return nil
		},
	}
	capturer := testCapturer(&recordingBrowserRunner{})
	factoryCalls := 0
	var runtimeConfig browserRuntimeConfig
	capturer.runtimeFactory = func(_ context.Context, config browserRuntimeConfig) (browserRuntime, error) {
		factoryCalls++
		runtimeConfig = config
		return runtime, nil
	}
	session := capturer.NewCaptureSession(context.Background())

	first := testCaptureRequest(t, "")
	second := captureRequestWithURL(t, first, "https://gateway.example.test/saml")
	if _, err := session.Capture(context.Background(), first); err != nil {
		t.Fatalf("first Capture() error = %v", err)
	}
	if _, err := session.Capture(context.Background(), second); err != nil {
		t.Fatalf("second Capture() error = %v", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("runtime factory calls = %d, want 1", factoryCalls)
	}
	if runtimeConfig.browserPath != testBrowserPath || runtimeConfig.profileDir != profileDir {
		t.Fatalf("runtime config = %#v, want browser %q and profile %q", runtimeConfig, testBrowserPath, profileDir)
	}
	wantTargets := []string{"https://portal.example.test/saml", "https://gateway.example.test/saml"}
	if !reflect.DeepEqual(runtime.targets(), wantTargets) {
		t.Fatalf("capture targets = %#v, want %#v", runtime.targets(), wantTargets)
	}
	if runtime.closed {
		t.Fatal("runtime closed before session Close")
	}

	if err := session.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if !reflect.DeepEqual(order, []string{"runtime", "profile"}) {
		t.Fatalf("close order = %#v, want runtime then profile", order)
	}
}

func Test_CaptureSession_rejectsBrowserOrProfileChanges(t *testing.T) {
	profileDir := filepath.Join(t.TempDir(), "persistent-profile")
	runtime := &recordingRuntime{artifact: testCaptureArtifact(t)}
	capturer := testCapturer(&recordingBrowserRunner{})
	capturer.runtimeFactory = fixedRuntimeFactory(runtime)
	session := capturer.NewCaptureSession(context.Background())
	t.Cleanup(func() { _ = session.Close() })
	request := testCaptureRequest(t, profileDir)
	if _, err := session.Capture(context.Background(), request); err != nil {
		t.Fatalf("initial Capture() error = %v", err)
	}

	tests := []struct {
		name   string
		change func(*Request)
	}{
		{name: "browser", change: func(request *Request) { request.Browser = BrowserEdge }},
		{name: "browser path", change: func(request *Request) { request.BrowserPath = "/other/browser" }},
		{name: "profile", change: func(request *Request) { request.ProfileDir = filepath.Join(t.TempDir(), "other") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := request
			test.change(&changed)
			_, err := session.Capture(context.Background(), changed)
			if !errors.Is(err, ErrCaptureConfigChanged) {
				t.Fatalf("Capture() error = %v, want ErrCaptureConfigChanged", err)
			}
		})
	}
	if got := len(runtime.targets()); got != 1 {
		t.Fatalf("runtime capture calls = %d, want 1", got)
	}
}

func Test_CaptureSession_cleansTemporaryProfileWhenRuntimeStartFails(t *testing.T) {
	profileDir := filepath.Join(t.TempDir(), "capture-profile")
	restoreProfileOS(t)
	osMkdirTemp = func(string, string) (string, error) {
		return profileDir, os.MkdirAll(profileDir, 0o700)
	}
	removed := false
	osRemoveAll = func(path string) error {
		removed = true
		return os.RemoveAll(path)
	}
	startErr := errors.New("runtime start failed")
	capturer := testCapturer(&recordingBrowserRunner{})
	capturer.runtimeFactory = func(context.Context, browserRuntimeConfig) (browserRuntime, error) {
		return nil, startErr
	}
	session := capturer.NewCaptureSession(context.Background())

	_, err := session.Capture(context.Background(), testCaptureRequest(t, ""))
	if !errors.Is(err, startErr) {
		t.Fatalf("Capture() error = %v, want runtime start error", err)
	}
	if !removed {
		t.Fatal("temporary profile was not removed after runtime start failure")
	}
	if closeErr := session.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}
}

func Test_CaptureSession_propagatesCaptureCancellationAndStillCloses(t *testing.T) {
	runtime := &recordingRuntime{artifact: testCaptureArtifact(t)}
	capturer := testCapturer(&recordingBrowserRunner{})
	capturer.runtimeFactory = fixedRuntimeFactory(runtime)
	session := capturer.NewCaptureSession(context.Background())
	request := testCaptureRequest(t, t.TempDir())
	if _, err := session.Capture(context.Background(), request); err != nil {
		t.Fatalf("initial Capture() error = %v", err)
	}

	captureCtx, cancel := context.WithCancel(context.Background())
	runtime.captureFunc = func(ctx context.Context) (gp.AuthArtifact, error) {
		cancel()
		<-ctx.Done()
		return gp.AuthArtifact{}, ctx.Err()
	}
	_, err := session.Capture(captureCtx, request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Capture() error = %v, want context.Canceled", err)
	}
	if runtime.closed {
		t.Fatal("capture cancellation closed the reusable runtime")
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !runtime.closed {
		t.Fatal("Close() did not close runtime")
	}
	if _, err := session.Capture(context.Background(), request); !errors.Is(err, ErrCaptureSessionClosed) {
		t.Fatalf("Capture() after Close error = %v, want ErrCaptureSessionClosed", err)
	}
}

func Test_CaptureSession_preservesExplicitProfileWhenRuntimeCloseFails(t *testing.T) {
	profileDir := filepath.Join(t.TempDir(), "persistent-profile")
	closeErr := errors.New("runtime close failed")
	runtime := &recordingRuntime{artifact: testCaptureArtifact(t), closeFunc: func() error { return closeErr }}
	capturer := testCapturer(&recordingBrowserRunner{})
	capturer.runtimeFactory = fixedRuntimeFactory(runtime)
	session := capturer.NewCaptureSession(context.Background())
	if _, err := session.Capture(context.Background(), testCaptureRequest(t, profileDir)); err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	if err := session.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want runtime close error", err)
	}
	if info, err := os.Stat(profileDir); err != nil || !info.IsDir() {
		t.Fatalf("persistent profile Stat() = (%v, %v), want directory", info, err)
	}
}

type recordingRuntime struct {
	artifact    gp.AuthArtifact
	requests    []runtimeCaptureRequest
	captureFunc func(context.Context) (gp.AuthArtifact, error)
	closeFunc   func() error
	closed      bool
}

func (r *recordingRuntime) capture(ctx context.Context, request runtimeCaptureRequest) (gp.AuthArtifact, error) {
	r.requests = append(r.requests, request)
	if r.captureFunc != nil {
		return r.captureFunc(ctx)
	}
	return r.artifact, nil
}

func (r *recordingRuntime) close() error {
	r.closed = true
	if r.closeFunc != nil {
		return r.closeFunc()
	}
	return nil
}

func (r *recordingRuntime) targets() []string {
	targets := make([]string, 0, len(r.requests))
	for _, request := range r.requests {
		targets = append(targets, request.target)
	}
	return targets
}

func fixedRuntimeFactory(runtime browserRuntime) browserRuntimeFactory {
	return func(context.Context, browserRuntimeConfig) (browserRuntime, error) { return runtime, nil }
}

func captureRequestWithURL(t *testing.T, request Request, rawURL string) Request {
	t.Helper()
	samlRequest, err := gp.NewSAMLRequest(rawURL)
	if err != nil {
		t.Fatalf("NewSAMLRequest() error = %v", err)
	}
	request.Prelogin.SAMLRequest = samlRequest
	return request
}
