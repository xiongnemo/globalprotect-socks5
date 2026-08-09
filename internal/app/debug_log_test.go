package app_test

import (
	"bytes"
	"context"
	"encoding/base64"
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

func Test_Run_serveWritesRedactedDebugLog_whenGatewayLoginRejected(t *testing.T) {
	// Given
	html := `<html><input name="SAMLRequest" value="secret-saml-request"></html>`
	encoded := base64.StdEncoding.EncodeToString([]byte(html))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/global-protect/prelogin.esp":
			_, _ = w.Write([]byte(`<prelogin-response><saml-auth-method>POST</saml-auth-method><saml-request>` + encoded + `</saml-request><saml-default-browser>yes</saml-default-browser></prelogin-response>`))
		case "/global-protect/getconfig.esp":
			_, _ = w.Write(portalPolicyResponse("http://" + r.Host))
		case "/ssl-vpn/prelogin.esp":
			_, _ = w.Write(gatewaySAMLPreloginResponse())
		case "/ssl-vpn/login.esp":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if got := r.Form.Get("portal-userauthcookie"); got != "portal-cookie" {
				t.Fatalf("portal-userauthcookie = %q, want portal-cookie", got)
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<response><error>gateway rejected login</error>` +
				`<portal-userauthcookie>portal-cookie</portal-userauthcookie>` +
				`<portal-prelogonuserauthcookie>portal-prelogon-cookie</portal-prelogonuserauthcookie>` +
				`<saml-request>secret-saml-request</saml-request></response>`))
		default:
			t.Fatalf("path = %s, want GlobalProtect endpoint", r.URL.Path)
		}
	}))
	defer server.Close()
	preloginCookie, err := gp.NewSecret("pre-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	debugPath := filepath.Join(t.TempDir(), "gp-debug.jsonl")
	capturer := &fakeAuthCapturer{artifact: gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	runner := app.NewRunner(app.IO{Stdout: &stdout, Stderr: &stderr, HTTPClient: server.Client(), AuthCapturer: capturer})

	// When
	err = runner.Run(context.Background(), []string{"serve", "--listen", "127.0.0.1:0", "--portal", server.URL, "--host-id", "test-host", "--browser", "chrome", "--timeout", "1s", "--debug-log", debugPath})

	// Then
	if !errors.Is(err, gp.ErrInvalidAuthArtifact) {
		t.Fatalf("Run() error = %v, want ErrInvalidAuthArtifact", err)
	}
	if capturer.request.ProfileDir == "" {
		t.Fatal("portal capture profile dir is empty")
	}
	if _, statErr := os.Stat(capturer.request.ProfileDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("temporary profile stat error = %v, want removed after authentication failure", statErr)
	}
	logBytes, err := os.ReadFile(debugPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	logText := string(logBytes)
	for _, want := range []string{"portal_config", "gateway_login", "/ssl-vpn/login.esp", "500", "prelogin-cookie", "portal-userauthcookie"} {
		if !strings.Contains(logText, want) {
			t.Fatalf("debug log = %q, want %q", logText, want)
		}
	}
	for _, secret := range []string{"pre-cookie", "portal-cookie", "portal-prelogon-cookie", "secret-saml-request"} {
		if strings.Contains(logText, secret) {
			t.Fatalf("debug log leaked %q: %q", secret, logText)
		}
		if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
			t.Fatalf("command output leaked %q: stdout=%q stderr=%q", secret, stdout.String(), stderr.String())
		}
	}
}

func Test_Run_serveReturnsBeforeAuth_whenDebugLogCannotOpen(t *testing.T) {
	// Given
	capturer := &fakeAuthCapturer{}
	httpCalls := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		httpCalls++
		return nil, errors.New("unexpected HTTP request")
	})}
	runner := app.NewRunner(app.IO{HTTPClient: httpClient, AuthCapturer: capturer})

	// When
	err := runner.Run(context.Background(), []string{"serve", "--portal", "https://portal.example.test", "--debug-log", t.TempDir()})

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
