package app_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Run_authPropagatesBrowserProfileDir_whenFlagProvided(t *testing.T) {
	// Given
	server := newBrowserProfilePreloginServer(t)
	defer server.Close()
	profileDir := t.TempDir()
	capturer := newBrowserProfileAuthCapturer(t)
	var stdout bytes.Buffer
	runner := app.NewRunner(app.IO{Stdout: &stdout, HTTPClient: server.Client(), AuthCapturer: capturer})

	// When
	err := runner.Run(context.Background(), []string{"auth", "--portal", server.URL, "--host-id", "test-host", "--browser", "chrome", "--browser-profile-dir", profileDir, "--timeout", "1s"})

	// Then
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !capturer.called {
		t.Fatal("auth capturer was not called")
	}
	if capturer.request.ProfileDir != profileDir {
		t.Fatalf("ProfileDir = %q, want %q", capturer.request.ProfileDir, profileDir)
	}
}

func Test_Run_authLeavesBrowserProfileDirEmpty_whenFlagOmitted(t *testing.T) {
	// Given
	server := newBrowserProfilePreloginServer(t)
	defer server.Close()
	capturer := newBrowserProfileAuthCapturer(t)
	var stdout bytes.Buffer
	runner := app.NewRunner(app.IO{Stdout: &stdout, HTTPClient: server.Client(), AuthCapturer: capturer})

	// When
	err := runner.Run(context.Background(), []string{"auth", "--portal", server.URL, "--host-id", "test-host", "--browser", "chrome", "--timeout", "1s"})

	// Then
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !capturer.called {
		t.Fatal("auth capturer was not called")
	}
	if capturer.request.ProfileDir != "" {
		t.Fatalf("ProfileDir = %q, want empty", capturer.request.ProfileDir)
	}
}

func newBrowserProfilePreloginServer(t *testing.T) *httptest.Server {
	t.Helper()
	html := `<html><body><form method="POST" action="https://idp.example.test/sso"></form></body></html>`
	encoded := base64.StdEncoding.EncodeToString([]byte(html))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/global-protect/prelogin.esp" {
			t.Fatalf("path = %s, want /global-protect/prelogin.esp", r.URL.Path)
		}
		_, _ = w.Write([]byte(`<prelogin-response><saml-auth-method>POST</saml-auth-method><saml-request>` + encoded + `</saml-request><saml-default-browser>yes</saml-default-browser></prelogin-response>`))
	}))
}

func newBrowserProfileAuthCapturer(t *testing.T) *fakeAuthCapturer {
	t.Helper()
	preloginCookie, err := gp.NewSecret("pre-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	return &fakeAuthCapturer{artifact: gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}}
}
