package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Run_rejectsInvalidExplicitGatewayAfterPortalConfig(t *testing.T) {
	// Given
	portalConfigCalled := make(chan struct{}, 1)
	server := newPortalConfigServer(t, portalConfigCalled, "http://127.0.0.1:1")
	defer server.Close()
	capturer := newBrowserProfileAuthCapturer(t)
	connector := newRecordingPacketTunnelConnector()
	stdout := newListenCapture()
	runner := app.NewRunner(app.IO{
		Stdout:                &stdout,
		HTTPClient:            server.Client(),
		AuthCapturer:          capturer,
		PacketTunnelConnector: connector,
	})

	// When
	err := runner.Run(context.Background(), []string{
		"serve", "--listen", "127.0.0.1:0",
		"--portal", server.URL, "--gateway", "http://",
		"--browser", "chrome", "--timeout", "1s",
	})

	// Then
	assertPortalConfigCalled(t, portalConfigCalled)
	if !errors.Is(err, gp.ErrInvalidPortalURL) || !strings.Contains(err.Error(), "gateway:") {
		t.Fatalf("Run() error = %v, want explicit gateway URL error", err)
	}
	if !capturer.called {
		t.Fatal("auth capturer was not called before portal config")
	}
	select {
	case request := <-connector.ready:
		t.Fatalf("packet tunnel connector called after invalid gateway: %#v", request)
	default:
	}
	select {
	case address := <-stdout.addr:
		t.Fatalf("serve listened at %q before rejecting invalid gateway", address)
	default:
	}
}

func Test_Run_rejectsGatewayWithoutPortalBeforeSideEffects(t *testing.T) {
	// Given
	stdout := newListenCapture()
	dialer := newRecordingDialer()
	t.Cleanup(dialer.closePeers)
	capturer := &fakeAuthCapturer{}
	runner := app.NewRunner(app.IO{
		Stdout:       &stdout,
		DialContext:  dialer.DialContext,
		AuthCapturer: capturer,
	})
	// When
	err := runner.Run(context.Background(), []string{"serve", "--listen", "127.0.0.1:0", "--gateway", "http://"})

	// Then
	if err == nil || !strings.Contains(err.Error(), "gateway requires a portal") {
		t.Fatalf("Run() error = %v, want gateway-without-portal validation error", err)
	}
	select {
	case <-stdout.addr:
		t.Fatal("serve listened before rejecting gateway without portal")
	default:
	}
	select {
	case <-dialer.ready:
		t.Fatal("serve dialed before rejecting gateway without portal")
	default:
	}
	if capturer.called {
		t.Fatal("auth capturer was called without a portal")
	}
}
