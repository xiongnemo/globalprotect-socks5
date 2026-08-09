package app_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

func TestRunServeReconnectsPacketTunnelAndKeepsLifetimeContext(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssl-vpn/prelogin.esp":
			_, _ = w.Write(gatewaySAMLPreloginResponse())
		case "/ssl-vpn/login.esp":
			_, _ = w.Write(gatewayLoginResponse())
		case "/ssl-vpn/getconfig.esp":
			_, _ = w.Write(gatewayConfigResponse())
		default:
			t.Fatalf("gateway path = %s, want GlobalProtect endpoint", r.URL.Path)
		}
	}))
	defer gateway.Close()
	portalCalled := make(chan struct{}, 1)
	portal := newPortalConfigServer(t, portalCalled, gateway.URL)
	defer portal.Close()
	connector := newSequencePacketTunnelConnector()
	stdout := newListenCapture()
	runner := app.NewRunner(app.IO{
		Stdout: &stdout, HTTPClient: portal.Client(),
		AuthCapturer: &fakeAuthCapturer{artifact: gp.AuthArtifact{
			Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: mustSecret(t, "pre-cookie"),
		}},
		PacketTunnelConnector: connector,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, []string{
			"serve", "--listen", "127.0.0.1:0", "--portal", portal.URL,
			"--host-id", "test-host", "--browser", "chrome", "--timeout", "1s",
		})
	}()

	listenAddr := stdout.wait(t)
	first := connector.wait(t)
	assertContextAlive(t, first.request.LifetimeContext, "initial lifetime")
	if err := first.tunnel.Close(); err != nil {
		t.Fatalf("close first packet tunnel: %v", err)
	}
	second := connector.wait(t)
	assertContextAlive(t, second.request.LifetimeContext, "replacement lifetime")
	waitContextCanceled(t, second.connectCtx)

	conn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	writeSOCKSGreeting(t, conn)
	if _, err := conn.Write(connectIPv4Request([4]byte{10, 41, 0, 1}, 443)); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	if packet := second.tunnel.waitWrite(t); len(packet) == 0 {
		t.Fatal("replacement packet tunnel write was empty")
	}
	cancel()
	assertServeStopped(t, errCh)
}

type packetTunnelCall struct {
	connectCtx context.Context
	request    app.PacketTunnelRequest
	tunnel     *recordingPacketTunnel
}

type sequencePacketTunnelConnector struct {
	calls chan packetTunnelCall
}

func newSequencePacketTunnelConnector() *sequencePacketTunnelConnector {
	return &sequencePacketTunnelConnector{calls: make(chan packetTunnelCall, 4)}
}

func (c *sequencePacketTunnelConnector) ConnectPacketTunnel(connectCtx context.Context, request app.PacketTunnelRequest) (tunnel.PacketTunnel, error) {
	packetTunnel := newRecordingPacketTunnel()
	c.calls <- packetTunnelCall{connectCtx: connectCtx, request: request, tunnel: packetTunnel}
	return packetTunnel, nil
}

func (c *sequencePacketTunnelConnector) wait(t *testing.T) packetTunnelCall {
	t.Helper()
	select {
	case call := <-c.calls:
		return call
	case <-time.After(time.Second):
		t.Fatal("packet tunnel connector was not called")
		return packetTunnelCall{}
	}
}

func assertContextAlive(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	if ctx == nil || ctx.Err() != nil {
		t.Fatalf("%s context = %v, want live context", name, ctx)
	}
}

func waitContextCanceled(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("connect context remained live after packet tunnel construction")
	}
}
