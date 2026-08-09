package app_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Run_serveFallsBackToGatewaySAML_whenPortalCookieRejectedWith512(t *testing.T) {
	// Given
	portalHTML := `<html><body><form method="POST" action="https://idp.example.test/portal"></form></body></html>`
	gatewayHTML := `<html><body><form method="POST" action="https://idp.example.test/gateway"><input name="SAMLRequest" value="gateway-saml-request"></form></body></html>`
	portalCookie := mustSecret(t, "portal-pre-cookie")
	gatewayCookie := mustSecret(t, "gateway-pre-cookie")
	endpoints := newGatewayFallbackEndpointRecorder()
	gatewayLoginForms := make(chan url.Values, 2)
	gatewayLoginCalls := newGatewayLoginCounter()
	gatewayServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		endpoints.record("gateway:" + request.URL.Path)
		switch request.URL.Path {
		case "/ssl-vpn/login.esp":
			gatewayLoginForms <- parsedForm(t, request)
			if gatewayLoginCalls.next() == 1 {
				response.WriteHeader(512)
				_, _ = response.Write([]byte(`<response><status>auth-failed</status><msg>retry required</msg></response>`))
				return
			}
			_, _ = response.Write(gatewayLoginResponse())
		case "/ssl-vpn/prelogin.esp":
			encoded := base64.StdEncoding.EncodeToString([]byte(gatewayHTML))
			_, _ = response.Write(preloginResponse(encoded))
		case "/ssl-vpn/getconfig.esp":
			_, _ = response.Write(gatewayConfigResponse())
		default:
			t.Fatalf("gateway path = %s, want fallback endpoint", request.URL.Path)
		}
	}))
	defer gatewayServer.Close()
	portalServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		endpoints.record("portal:" + request.URL.Path)
		switch request.URL.Path {
		case "/global-protect/prelogin.esp":
			encoded := base64.StdEncoding.EncodeToString([]byte(portalHTML))
			_, _ = response.Write(preloginResponse(encoded))
		case "/global-protect/getconfig.esp":
			form := parsedForm(t, request)
			if form.Get("prelogin-cookie") != "portal-pre-cookie" {
				t.Fatal("portal config did not use the portal prelogin cookie")
			}
			_, _ = response.Write(portalPolicyResponse(gatewayServer.URL))
		default:
			t.Fatalf("portal path = %s, want portal endpoint", request.URL.Path)
		}
	}))
	defer portalServer.Close()
	stdout := newListenCapture()
	capturer := newGatewayFallbackAuthCapturer(
		gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: portalCookie},
		gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: gatewayCookie},
	)
	connector := newRecordingPacketTunnelConnector()
	directDialer := newRecordingDialer()
	t.Cleanup(directDialer.closePeers)
	runner := app.NewRunner(app.IO{Stdout: &stdout, HTTPClient: portalServer.Client(), AuthCapturer: capturer, DialContext: directDialer.DialContext, PacketTunnelConnector: connector})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, []string{"serve", "--listen", "127.0.0.1:0", "--portal", portalServer.URL, "--host-id", "test-host", "--browser", "chrome", "--browser-path", "test-browser", "--timeout", "1s"})
	}()
	var listenAddress string
	select {
	case listenAddress = <-stdout.addr:
	case err := <-errCh:
		if errors.Is(err, gp.ErrGatewayAuthFailed) {
			t.Fatalf("Run() returned initial gateway auth failure before gateway prelogin fallback; endpoints=%#v", endpoints.drain())
		}
		t.Fatalf("Run() returned before gateway prelogin fallback completed: %v; endpoints=%#v", err, endpoints.drain())
	case <-time.After(time.Second):
		stdout.mu.Lock()
		text := stdout.text
		stdout.mu.Unlock()
		t.Fatalf("serve did not print listen address; stdout=%q endpoints=%#v", text, endpoints.drain())
	}
	conn := dialServeListener(t, listenAddress)
	defer conn.Close()
	writeSOCKSGreeting(t, conn)

	// When
	if _, err := conn.Write(connectIPv4Request([4]byte{10, 41, 0, 1}, 443)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	packet := connector.tunnel.waitWrite(t)
	request := connector.wait(t)
	captureRequests := capturer.waitRequests(t, 2)
	initialLoginForm := waitForm(t, gatewayLoginForms)
	retryLoginForm := waitForm(t, gatewayLoginForms)
	gotEndpoints := endpoints.wait(t, 6)
	cancel()

	// Then
	wantEndpoints := []string{
		"portal:/global-protect/prelogin.esp",
		"portal:/global-protect/getconfig.esp",
		"gateway:/ssl-vpn/prelogin.esp",
		"gateway:/ssl-vpn/login.esp",
		"gateway:/ssl-vpn/login.esp",
		"gateway:/ssl-vpn/getconfig.esp",
	}
	if !slices.Equal(gotEndpoints, wantEndpoints) {
		t.Fatalf("endpoints = %#v, want %#v", gotEndpoints, wantEndpoints)
	}
	if initialLoginForm.Get("portal-userauthcookie") != "portal-cookie" {
		t.Fatal("initial gateway login did not use the portal user auth cookie")
	}
	if initialLoginForm.Get("portal-prelogonuserauthcookie") != "portal-prelogon-cookie" {
		t.Fatal("initial gateway login did not use the portal prelogon auth cookie")
	}
	if !initialLoginForm.Has("prelogin-cookie") || initialLoginForm.Get("prelogin-cookie") != "" {
		t.Fatalf("initial gateway login prelogin-cookie fields = %#v, want present and empty", formKeys(initialLoginForm))
	}
	if retryLoginForm.Get("prelogin-cookie") != "gateway-pre-cookie" {
		t.Fatal("gateway retry login did not use the gateway prelogin cookie")
	}
	if retryLoginForm.Get("portal-userauthcookie") != "empty" || retryLoginForm.Get("portal-prelogonuserauthcookie") != "empty" {
		t.Fatalf("gateway retry portal cookie sentinels = %#v, want empty", retryLoginForm)
	}
	if captureRequests[0].Prelogin.SAMLRequest.String() != portalHTML {
		t.Fatal("initial capture did not receive portal SAML prelogin")
	}
	if captureRequests[1].Prelogin.SAMLRequest.String() != gatewayHTML {
		t.Fatal("fallback capture did not receive gateway SAML prelogin")
	}
	if captureRequests[1].Browser != captureRequests[0].Browser || captureRequests[1].Browser != browserauth.BrowserChrome {
		t.Fatalf("fallback browser = %q, want chrome from initial capture", captureRequests[1].Browser)
	}
	if captureRequests[1].BrowserPath != captureRequests[0].BrowserPath || captureRequests[1].BrowserPath != "test-browser" {
		t.Fatalf("fallback browser path = %q, want initial browser path", captureRequests[1].BrowserPath)
	}
	if captureRequests[1].ProfileDir != captureRequests[0].ProfileDir {
		t.Fatalf("fallback profile dir = %q, want same profile dir", captureRequests[1].ProfileDir)
	}
	if captureRequests[0].ProfileDir == "" || !filepath.IsAbs(captureRequests[0].ProfileDir) {
		t.Fatalf("shared profile dir = %q, want non-empty absolute temp directory", captureRequests[0].ProfileDir)
	}
	if _, err := os.Stat(captureRequests[0].ProfileDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary profile stat error = %v, want profile removed after authentication", err)
	}
	if captureRequests[1].Timeout != captureRequests[0].Timeout || captureRequests[1].Timeout != time.Second {
		t.Fatalf("fallback timeout = %s, want initial timeout", captureRequests[1].Timeout)
	}
	if len(packet) == 0 {
		t.Fatal("packet tunnel write was empty")
	}
	if request.Gateway.TCPAddress() != serverTCPAddress(t, gatewayServer.URL) {
		t.Fatalf("gateway = %s, want fallback gateway", request.Gateway.TCPAddress())
	}
	if request.Session.User != "alice@example.test" {
		t.Fatalf("connector user = %q, want alice@example.test", request.Session.User)
	}
	if request.Config.IP.String() != "10.41.0.12" {
		t.Fatalf("connector config IP = %s, want 10.41.0.12", request.Config.IP)
	}
	assertDirectDialerIdle(t, directDialer)
	assertServeStopped(t, errCh)
}

func Test_Run_serveReturnsGatewayLoginError_whenGatewayLoginFailureIsNotSentinel(t *testing.T) {
	// Given
	portalHTML := `<html><body><form method="POST" action="https://idp.example.test/portal"></form></body></html>`
	portalCookie := mustSecret(t, "portal-pre-cookie")
	endpoints := newGatewayFallbackEndpointRecorder()
	gatewayServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		endpoints.record("gateway:" + request.URL.Path)
		switch request.URL.Path {
		case "/ssl-vpn/prelogin.esp":
			encoded := base64.StdEncoding.EncodeToString([]byte(portalHTML))
			_, _ = response.Write(preloginResponse(encoded))
		case "/ssl-vpn/login.esp":
			response.WriteHeader(http.StatusInternalServerError)
			_, _ = response.Write([]byte(`<response><status>error</status><msg>temporary gateway failure</msg></response>`))
		default:
			t.Fatalf("gateway path = %s, want prelogin then initial login", request.URL.Path)
		}
	}))
	defer gatewayServer.Close()
	portalServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		endpoints.record("portal:" + request.URL.Path)
		switch request.URL.Path {
		case "/global-protect/prelogin.esp":
			encoded := base64.StdEncoding.EncodeToString([]byte(portalHTML))
			_, _ = response.Write(preloginResponse(encoded))
		case "/global-protect/getconfig.esp":
			_, _ = response.Write(portalPolicyResponse(gatewayServer.URL))
		default:
			t.Fatalf("portal path = %s, want portal endpoint", request.URL.Path)
		}
	}))
	defer portalServer.Close()
	capturer := newGatewayFallbackAuthCapturer(gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: portalCookie})
	runner := app.NewRunner(app.IO{HTTPClient: portalServer.Client(), AuthCapturer: capturer, PacketTunnelConnector: newRecordingPacketTunnelConnector()})

	// When
	err := runner.Run(context.Background(), []string{"serve", "--listen", "127.0.0.1:0", "--portal", portalServer.URL, "--host-id", "test-host", "--browser", "chrome", "--timeout", "1s"})

	// Then
	if err == nil {
		t.Fatal("Run() error = nil, want gateway login error")
	}
	if errors.Is(err, gp.ErrGatewayAuthFailed) {
		t.Fatalf("Run() error = %v, want non-sentinel gateway login failure", err)
	}
	wantEndpoints := []string{
		"portal:/global-protect/prelogin.esp",
		"portal:/global-protect/getconfig.esp",
		"gateway:/ssl-vpn/prelogin.esp",
		"gateway:/ssl-vpn/login.esp",
	}
	gotEndpoints := endpoints.wait(t, len(wantEndpoints))
	if !slices.Equal(gotEndpoints, wantEndpoints) {
		t.Fatalf("endpoints = %#v, want %#v", gotEndpoints, wantEndpoints)
	}
	endpoints.assertIdle(t)
	if capturer.count() != 1 {
		t.Fatalf("auth captures = %d, want only the portal capture", capturer.count())
	}
}
