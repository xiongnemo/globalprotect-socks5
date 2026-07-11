package app_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Run_serveSelectsExternalGatewayFromPortalConfig_whenGatewayFlagAbsent(t *testing.T) {
	// Given
	preloginCookie := mustSecret(t, "pre-cookie")
	portalConfigCalled := make(chan struct{}, 1)
	gatewayLoginForm := make(chan url.Values, 1)
	gatewayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssl-vpn/login.esp":
			gatewayLoginForm <- parsedForm(t, r)
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
	capturer := &fakeAuthCapturer{artifact: gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}}
	connector := newRecordingPacketTunnelConnector()
	directDialer := newRecordingDialer()
	t.Cleanup(directDialer.closePeers)
	runner := app.NewRunner(app.IO{Stdout: &stdout, HTTPClient: portalServer.Client(), AuthCapturer: capturer, DialContext: directDialer.DialContext, PacketTunnelConnector: connector})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, []string{"serve", "--listen", "127.0.0.1:0", "--portal", portalServer.URL, "--host-id", "test-host", "--browser", "chrome", "--timeout", "1s"})
	}()
	conn := dialServeListener(t, stdout.wait(t))
	defer conn.Close()
	writeSOCKSGreeting(t, conn)

	// When
	if _, err := conn.Write(connectIPv4Request([4]byte{10, 41, 0, 1}, 443)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	packet := connector.tunnel.waitWrite(t)
	request := connector.wait(t)
	form := waitForm(t, gatewayLoginForm)
	cancel()

	// Then
	if len(packet) == 0 {
		t.Fatal("packet tunnel write was empty")
	}
	if request.Gateway.TCPAddress() != serverTCPAddress(t, gatewayServer.URL) {
		t.Fatalf("gateway = %s, want selected external gateway", request.Gateway.TCPAddress())
	}
	assertPortalConfigCalled(t, portalConfigCalled)
	if got := form.Get("portal-userauthcookie"); got != "portal-cookie" {
		t.Fatalf("portal-userauthcookie = %q, want portal-cookie", got)
	}
	if form.Has("prelogin-cookie") {
		t.Fatalf("gateway login form included prelogin-cookie after portal config: %#v", form)
	}
	assertServeStopped(t, errCh)
	assertDirectDialerIdle(t, directDialer)
	if !capturer.called {
		t.Fatal("auth capturer was not called")
	}
}

func Test_Run_serveUsesExplicitGatewayAfterPortalConfig_whenGatewayFlagPresent(t *testing.T) {
	// Given
	preloginCookie := mustSecret(t, "pre-cookie")
	portalConfigCalled := make(chan struct{}, 1)
	gatewayLoginForm := make(chan url.Values, 1)
	gatewayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssl-vpn/login.esp":
			gatewayLoginForm <- parsedForm(t, r)
			_, _ = w.Write(gatewayLoginResponse())
		case "/ssl-vpn/getconfig.esp":
			_, _ = w.Write(gatewayConfigResponse())
		default:
			t.Fatalf("gateway path = %s, want GlobalProtect gateway endpoint", r.URL.Path)
		}
	}))
	defer gatewayServer.Close()
	portalServer := newPortalConfigServer(t, portalConfigCalled, "http://127.0.0.1:1")
	defer portalServer.Close()
	stdout := newListenCapture()
	capturer := &fakeAuthCapturer{artifact: gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}}
	connector := newRecordingPacketTunnelConnector()
	runner := app.NewRunner(app.IO{Stdout: &stdout, HTTPClient: portalServer.Client(), AuthCapturer: capturer, PacketTunnelConnector: connector})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, []string{"serve", "--listen", "127.0.0.1:0", "--portal", portalServer.URL, "--gateway", gatewayServer.URL, "--host-id", "test-host", "--browser", "chrome", "--timeout", "1s"})
	}()
	conn := dialServeListener(t, stdout.wait(t))
	defer conn.Close()
	writeSOCKSGreeting(t, conn)

	// When
	if _, err := conn.Write(connectIPv4Request([4]byte{10, 41, 0, 1}, 443)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = connector.tunnel.waitWrite(t)
	request := connector.wait(t)
	form := waitForm(t, gatewayLoginForm)
	cancel()

	// Then
	if request.Gateway.TCPAddress() != serverTCPAddress(t, gatewayServer.URL) {
		t.Fatalf("gateway = %s, want explicit gateway", request.Gateway.TCPAddress())
	}
	assertPortalConfigCalled(t, portalConfigCalled)
	if got := form.Get("portal-userauthcookie"); got != "portal-cookie" {
		t.Fatalf("portal-userauthcookie = %q, want portal-cookie", got)
	}
	if form.Has("prelogin-cookie") {
		t.Fatalf("gateway login form included prelogin-cookie after portal config: %#v", form)
	}
	assertServeStopped(t, errCh)
	if !capturer.called {
		t.Fatal("auth capturer was not called")
	}
}

func newPortalConfigServer(t *testing.T, portalConfigCalled chan<- struct{}, gatewayRaw string) *httptest.Server {
	t.Helper()
	html := `<html><body><form method="POST" action="https://idp.example.test/sso"></form></body></html>`
	encoded := base64.StdEncoding.EncodeToString([]byte(html))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/global-protect/prelogin.esp":
			_, _ = w.Write(preloginResponse(encoded))
		case "/global-protect/getconfig.esp":
			form := parsedForm(t, r)
			if got := form.Get("prelogin-cookie"); got != "pre-cookie" {
				t.Fatalf("portal prelogin-cookie = %q, want pre-cookie", got)
			}
			portalConfigCalled <- struct{}{}
			_, _ = w.Write(portalPolicyResponse(gatewayRaw))
		default:
			t.Fatalf("portal path = %s, want GlobalProtect portal endpoint", r.URL.Path)
		}
	}))
}

func assertServeStopped(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve command did not stop after cancellation")
	}
}

func assertDirectDialerIdle(t *testing.T, dialer *recordingDialer) {
	t.Helper()
	select {
	case <-dialer.ready:
		t.Fatal("direct dialer was called despite portal-backed serve")
	default:
	}
}

func serverTCPAddress(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return parsed.Host
}

func preloginResponse(encoded string) []byte {
	return []byte(`<prelogin-response><saml-auth-method>POST</saml-auth-method><saml-request>` + encoded + `</saml-request><saml-default-browser>yes</saml-default-browser></prelogin-response>`)
}

func portalPolicyResponse(gatewayRaw string) []byte {
	return []byte(`<policy><portal-userauthcookie>portal-cookie</portal-userauthcookie><gateways><external><list><entry name="` + gatewayRaw + `"><description>Gateway</description></entry></list></external></gateways></policy>`)
}

func gatewayLoginResponse() []byte {
	return []byte(`<jnlp><application-desc>` +
		`<argument></argument>` +
		`<argument>auth-cookie</argument>` +
		`<argument>persistent-cookie</argument>` +
		`<argument>vpn.example.test</argument>` +
		`<argument>alice@example.test</argument>` +
		`<argument>saml</argument>` +
		`<argument>config</argument>` +
		`<argument>EXAMPLE</argument>` +
		`<argument>unused</argument>` +
		`<argument>unused</argument>` +
		`<argument>test-host</argument>` +
		`<argument>unused</argument>` +
		`<argument>tunnel</argument>` +
		`<argument>-1</argument>` +
		`<argument>4100</argument>` +
		`<argument>10.41.0.12</argument>` +
		`</application-desc></jnlp>`)
}

func gatewayConfigResponse() []byte {
	return []byte(`<response status="success"><result>` +
		`<ip-address>10.41.0.12</ip-address>` +
		`<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>` +
		`</result></response>`)
}
