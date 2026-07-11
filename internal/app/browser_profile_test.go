package app_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
)

func Test_Run_servePropagatesBrowserProfileDir_whenPortalProvided(t *testing.T) {
	// Given
	profileDir := t.TempDir()
	portalConfigCalled := make(chan struct{}, 1)
	gatewayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssl-vpn/login.esp":
			_, _ = w.Write(gatewayLoginResponse())
		case "/ssl-vpn/getconfig.esp":
			_, _ = w.Write(gatewayConfigResponse())
		default:
			t.Fatalf("gateway path = %s, want GlobalProtect gateway endpoint", r.URL.Path)
		}
	}))
	defer gatewayServer.Close()
	portalServer := newPortalConfigServer(t, portalConfigCalled, gatewayServer.URL)
	defer portalServer.Close()
	stdout := newListenCapture()
	capturer := newBrowserProfileAuthCapturer(t)
	connector := newRecordingPacketTunnelConnector()
	runner := app.NewRunner(app.IO{Stdout: &stdout, HTTPClient: portalServer.Client(), AuthCapturer: capturer, PacketTunnelConnector: connector})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, []string{"serve", "--listen", "127.0.0.1:0", "--portal", portalServer.URL, "--host-id", "test-host", "--browser", "chrome", "--browser-profile-dir", profileDir, "--timeout", "1s"})
	}()

	// When
	select {
	case <-stdout.addr:
	case err := <-errCh:
		t.Fatalf("Run() error before listen = %v", err)
	case <-time.After(time.Second):
		stdout.mu.Lock()
		text := stdout.text
		stdout.mu.Unlock()
		t.Fatalf("serve did not print listen address; stdout=%q", text)
	}
	_ = connector.wait(t)
	assertPortalConfigCalled(t, portalConfigCalled)
	cancel()

	// Then
	if !capturer.called {
		t.Fatal("auth capturer was not called")
	}
	if capturer.request.ProfileDir != profileDir {
		t.Fatalf("ProfileDir = %q, want %q", capturer.request.ProfileDir, profileDir)
	}
	assertServeStopped(t, errCh)
}
