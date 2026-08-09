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

func Test_Run_ignoresInvalidGatewayWithoutPortal(t *testing.T) {
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, []string{"serve", "--listen", "127.0.0.1:0", "--gateway", "http://"})
	}()
	conn := dialServeListener(t, stdout.wait(t))
	defer conn.Close()
	writeSOCKSGreeting(t, conn)

	// When
	if _, err := conn.Write(connectRequest("example.test", 443)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	reply := make([]byte, 10)
	if _, err := conn.Read(reply); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	network, address := dialer.wait(t)
	cancel()

	// Then
	if network != "tcp" || address != "example.test:443" {
		t.Fatalf("direct dial = %q %q, want tcp example.test:443", network, address)
	}
	if reply[1] != 0x00 {
		t.Fatalf("SOCKS reply = %#v, want success", reply)
	}
	assertServeStopped(t, errCh)
	if capturer.called {
		t.Fatal("auth capturer was called without a portal")
	}
}
