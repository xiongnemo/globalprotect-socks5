package app_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
)

func Test_Run_authMergesFileEnvironmentAndCLIByField(t *testing.T) {
	// Given
	forms := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		forms <- parsedForm(t, request)
		html := `<form method="POST" action="https://idp.example.test/sso"></form>`
		encoded := base64.StdEncoding.EncodeToString([]byte(html))
		_, _ = w.Write(preloginResponse(encoded))
	}))
	defer server.Close()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	writeRunnerConfig(t, configPath, fmt.Sprintf(`auth:
  portal: %q
  browser: "chrome"
  browser_path: "file-browser"
  host_id: "file-host"
`, server.URL))
	capturer := newBrowserProfileAuthCapturer(t)
	environment := map[string]string{
		"GP_SOCKS_BROWSER": "edge",
		"GP_SOCKS_HOST_ID": "env-host",
	}
	runner := app.NewRunner(app.IO{
		HTTPClient:   server.Client(),
		AuthCapturer: capturer,
		LookupEnv: func(name string) (string, bool) {
			value, found := environment[name]
			return value, found
		},
	})

	// When
	err := runner.Run(context.Background(), []string{
		"--config", configPath,
		"auth", "--timeout", "17s", "--host-id", "cli-host",
	})

	// Then
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	form := waitForm(t, forms)
	if got := form.Get("host-id"); got != "cli-host" {
		t.Fatalf("prelogin host-id = %q, want cli-host", got)
	}
	if capturer.request.Browser != browserauth.BrowserEdge {
		t.Fatalf("Browser = %q, want edge", capturer.request.Browser)
	}
	if capturer.request.BrowserPath != "file-browser" {
		t.Fatalf("BrowserPath = %q, want file-browser", capturer.request.BrowserPath)
	}
	if capturer.request.Timeout != 17*time.Second {
		t.Fatalf("Timeout = %s, want 17s", capturer.request.Timeout)
	}
}

func Test_Run_opensMergedDebugLogBeforeRuntimeValidation(t *testing.T) {
	// Given
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	debugLogDirectory := t.TempDir()
	writeRunnerConfig(t, configPath, fmt.Sprintf(`auth:
  debug_log: %q
  browser: "invalid-browser"
  portal: "http://"
`, debugLogDirectory))
	httpCalls := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		httpCalls++
		return nil, fmt.Errorf("unexpected HTTP request")
	})}
	capturer := &fakeAuthCapturer{}
	runner := app.NewRunner(app.IO{
		HTTPClient:   httpClient,
		AuthCapturer: capturer,
		LookupEnv:    func(string) (string, bool) { return "", false },
	})

	// When
	err := runner.Run(context.Background(), []string{"--config", configPath, "auth"})

	// Then
	if err == nil || !strings.Contains(err.Error(), "open debug log") {
		t.Fatalf("Run() error = %v, want debug-log open failure", err)
	}
	if httpCalls != 0 {
		t.Fatalf("HTTP calls = %d, want 0", httpCalls)
	}
	if capturer.called {
		t.Fatal("auth capturer was called after debug-log open failure")
	}
}

func writeRunnerConfig(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
