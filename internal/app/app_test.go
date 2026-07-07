package app_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Run_printsAuthArtifactSummary_whenParseAuthReceivesCallback(t *testing.T) {
	// Given
	var stdout bytes.Buffer
	args := []string{"parse-auth", "globalprotectcallback:cas-as=1&un=alice&token=secret-token"}
	runner := app.NewRunner(app.IO{Stdout: &stdout})

	// When
	err := runner.Run(context.Background(), args)

	// Then
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "kind=cas") {
		t.Fatalf("stdout = %q, want kind=cas", out)
	}
	if !strings.Contains(out, "username=alice") {
		t.Fatalf("stdout = %q, want username=alice", out)
	}
	if strings.Contains(out, "secret-token") {
		t.Fatalf("stdout leaked token: %q", out)
	}
}

func Test_Run_probesPortalPrelogin_whenProbeCommandReceivesPortal(t *testing.T) {
	// Given
	loginURL := "https://idp.example.test/login?SAMLRequest=abc"
	encoded := base64.StdEncoding.EncodeToString([]byte(loginURL))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/global-protect/prelogin.esp" {
			t.Fatalf("path = %s, want /global-protect/prelogin.esp", r.URL.Path)
		}
		_, _ = w.Write([]byte(`<prelogin-response><saml-auth-method>REDIRECT</saml-auth-method><saml-request>` + encoded + `</saml-request><saml-default-browser>yes</saml-default-browser></prelogin-response>`))
	}))
	defer server.Close()
	var stdout bytes.Buffer
	runner := app.NewRunner(app.IO{Stdout: &stdout, HTTPClient: server.Client()})

	// When
	err := runner.Run(context.Background(), []string{"probe", "--portal", server.URL, "--host-id", "test-host"})

	// Then
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "auth=saml") {
		t.Fatalf("stdout = %q, want auth=saml", out)
	}
	if !strings.Contains(out, "default_browser=true") {
		t.Fatalf("stdout = %q, want default_browser=true", out)
	}
}

func Test_Run_writesPostSSOHTML_whenProbeReceivesSAMLPostAndFilePath(t *testing.T) {
	// Given
	html := `<html><body><form method="POST" action="https://idp.example.test/sso"></form></body></html>`
	encoded := base64.StdEncoding.EncodeToString([]byte(html))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<prelogin-response><saml-auth-method>POST</saml-auth-method><saml-request>` + encoded + `</saml-request><saml-default-browser>yes</saml-default-browser></prelogin-response>`))
	}))
	defer server.Close()
	var stdout bytes.Buffer
	ssoFile := filepath.Join(t.TempDir(), "sso.html")
	runner := app.NewRunner(app.IO{Stdout: &stdout, HTTPClient: server.Client()})

	// When
	err := runner.Run(context.Background(), []string{"probe", "--portal", server.URL, "--host-id", "test-host", "--sso-file", ssoFile})

	// Then
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	written, err := os.ReadFile(ssoFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(written) != html {
		t.Fatalf("sso file = %q, want html", string(written))
	}
	out := stdout.String()
	if !strings.Contains(out, "sso_file=") {
		t.Fatalf("stdout = %q, want sso_file", out)
	}
	if strings.Contains(out, html) {
		t.Fatalf("stdout leaked post html: %q", out)
	}
}

func Test_Run_printsRedactedAuthSummary_whenAuthCommandCapturesSAMLArtifact(t *testing.T) {
	// Given
	html := `<html><body><form method="POST" action="https://idp.example.test/sso"><input name="SAMLRequest" value="secret-saml-request"></form></body></html>`
	encoded := base64.StdEncoding.EncodeToString([]byte(html))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/global-protect/prelogin.esp" {
			t.Fatalf("path = %s, want /global-protect/prelogin.esp", r.URL.Path)
		}
		_, _ = w.Write([]byte(`<prelogin-response><saml-auth-method>POST</saml-auth-method><saml-request>` + encoded + `</saml-request><saml-default-browser>yes</saml-default-browser></prelogin-response>`))
	}))
	defer server.Close()
	preloginCookie, err := gp.NewSecret("pre-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	capturer := &fakeAuthCapturer{artifact: gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}}
	var stdout bytes.Buffer
	runner := app.NewRunner(app.IO{Stdout: &stdout, HTTPClient: server.Client(), AuthCapturer: capturer})

	// When
	err = runner.Run(context.Background(), []string{"auth", "--portal", server.URL, "--host-id", "test-host", "--browser", "chrome", "--timeout", "1s"})

	// Then
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !capturer.called {
		t.Fatal("auth capturer was not called")
	}
	if capturer.request.Browser != browserauth.BrowserChrome {
		t.Fatalf("Browser = %q, want %q", capturer.request.Browser, browserauth.BrowserChrome)
	}
	if capturer.request.Prelogin.SAMLRequest.String() != html {
		t.Fatalf("SAMLRequest = %q, want original POST HTML", capturer.request.Prelogin.SAMLRequest.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "kind=saml username=alice@example.test") {
		t.Fatalf("stdout = %q, want redacted SAML summary", out)
	}
	if !strings.Contains(out, "prelogin_cookie_present=true") {
		t.Fatalf("stdout = %q, want prelogin cookie presence", out)
	}
	if strings.Contains(out, "pre-cookie") || strings.Contains(out, "secret-saml-request") || strings.Contains(out, html) {
		t.Fatalf("stdout leaked secret material: %q", out)
	}
}

func Test_Run_rejectsPasswordAuthPrelogin_whenAuthCommandNeedsSAML(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<prelogin-response><auth-method>LDAP</auth-method></prelogin-response>`))
	}))
	defer server.Close()
	capturer := &fakeAuthCapturer{}
	runner := app.NewRunner(app.IO{HTTPClient: server.Client(), AuthCapturer: capturer})

	// When
	err := runner.Run(context.Background(), []string{"auth", "--portal", server.URL})

	// Then
	if !errors.Is(err, gp.ErrInvalidPrelogin) {
		t.Fatalf("error = %v, want ErrInvalidPrelogin", err)
	}
	if capturer.called {
		t.Fatal("auth capturer was called for password prelogin")
	}
}

func Test_Run_servesSOCKS5Greeting_whenServeCommandStarts(t *testing.T) {
	// Given
	stdout := newListenCapture()
	runner := app.NewRunner(app.IO{Stdout: &stdout})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runner.Run(ctx, []string{"serve", "--listen", "127.0.0.1:0"}) }()
	addr := stdout.wait(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	// When
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	cancel()

	// Then
	if response[0] != 0x05 || response[1] != 0x00 {
		t.Fatalf("SOCKS greeting response = %#v, want 0500", response)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve command did not stop after cancellation")
	}
}

type listenCapture struct {
	mu   sync.Mutex
	text string
	addr chan string
}

type fakeAuthCapturer struct {
	artifact gp.AuthArtifact
	request  browserauth.Request
	called   bool
}

func (c *fakeAuthCapturer) Capture(_ context.Context, request browserauth.Request) (gp.AuthArtifact, error) {
	c.called = true
	c.request = request
	return c.artifact, nil
}

func newListenCapture() listenCapture {
	return listenCapture{addr: make(chan string, 1)}
}

func (w *listenCapture) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.text += string(p)
	line := w.text
	w.mu.Unlock()
	if addr, ok := strings.CutPrefix(line, "listening="); ok {
		select {
		case w.addr <- strings.TrimSpace(addr):
		default:
		}
	}
	return len(p), nil
}

func (w *listenCapture) wait(t *testing.T) string {
	t.Helper()
	select {
	case addr := <-w.addr:
		return addr
	case <-time.After(time.Second):
		w.mu.Lock()
		defer w.mu.Unlock()
		t.Fatalf("serve did not print listen address; stdout=%q", w.text)
		return ""
	}
}
