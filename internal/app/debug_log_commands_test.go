package app_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Run_probeWritesRedactedDebugLog_whenPreloginRejected(t *testing.T) {
	// Given
	server := newRejectedPreloginServer(t)
	defer server.Close()
	debugPath := filepath.Join(t.TempDir(), "probe.jsonl")
	runner := app.NewRunner(app.IO{HTTPClient: server.Client()})

	// When
	err := runner.Run(context.Background(), []string{"probe", "--portal", server.URL, "--debug-log", debugPath})

	// Then
	assertRejectedPreloginDebugLog(t, err, debugPath)
}

func Test_Run_authWritesRedactedDebugLog_whenPreloginRejected(t *testing.T) {
	// Given
	server := newRejectedPreloginServer(t)
	defer server.Close()
	debugPath := filepath.Join(t.TempDir(), "auth.jsonl")
	capturer := &fakeAuthCapturer{}
	runner := app.NewRunner(app.IO{HTTPClient: server.Client(), AuthCapturer: capturer})

	// When
	err := runner.Run(context.Background(), []string{"auth", "--portal", server.URL, "--debug-log", debugPath})

	// Then
	assertRejectedPreloginDebugLog(t, err, debugPath)
	if capturer.called {
		t.Fatal("auth capturer was called after rejected prelogin")
	}
}

func Test_Run_authReturnsBeforeCapture_whenDebugLogCannotOpen(t *testing.T) {
	// Given
	capturer := &fakeAuthCapturer{}
	httpCalls := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		httpCalls++
		return nil, errors.New("unexpected HTTP request")
	})}
	runner := app.NewRunner(app.IO{HTTPClient: httpClient, AuthCapturer: capturer})

	// When
	err := runner.Run(context.Background(), []string{"auth", "--portal", "https://portal.example.test", "--debug-log", t.TempDir()})

	// Then
	if err == nil || !strings.Contains(err.Error(), "open debug log") {
		t.Fatalf("Run() error = %v, want debug log open error", err)
	}
	if httpCalls != 0 {
		t.Fatalf("HTTP calls = %d, want 0", httpCalls)
	}
	if capturer.called {
		t.Fatal("auth capturer was called after debug log open failure")
	}
}

func newRejectedPreloginServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/global-protect/prelogin.esp" {
			t.Fatalf("path = %s, want prelogin endpoint", r.URL.Path)
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<response><message>diagnostic</message><prelogin-cookie>secret-cookie</prelogin-cookie><saml-request>secret-saml</saml-request></response>`))
	}))
}

func assertRejectedPreloginDebugLog(t *testing.T, runErr error, path string) {
	t.Helper()
	if !errors.Is(runErr, gp.ErrInvalidPrelogin) {
		t.Fatalf("Run() error = %v, want ErrInvalidPrelogin", runErr)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	text := string(contents)
	for _, want := range []string{`"stage":"prelogin"`, `"path":"/global-protect/prelogin.esp"`, `"status":500`, "diagnostic"} {
		if !strings.Contains(text, want) {
			t.Fatalf("debug log = %q, want %q", text, want)
		}
	}
	for _, secret := range []string{"secret-cookie", "secret-saml"} {
		if strings.Contains(text, secret) {
			t.Fatalf("debug log leaked %q: %q", secret, text)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
