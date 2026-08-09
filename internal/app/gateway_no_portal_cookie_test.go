package app_test

import (
	"bytes"
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

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Run_serveUsesGatewaySAMLDirectly_whenPortalConfigHasNoCookies(t *testing.T) {
	portalHTML := `<html><form method="POST" action="https://idp.example.test/portal"></form></html>`
	gatewayHTML := `<html><form method="POST" action="https://idp.example.test/gateway"></form></html>`
	portalCookie := mustSecret(t, "portal-pre-cookie")
	gatewayCookie := mustSecret(t, "gateway-pre-cookie")
	endpoints := newGatewayFallbackEndpointRecorder()
	loginForms := make(chan url.Values, 1)

	gatewayServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		endpoints.record("gateway:" + request.URL.Path)
		switch request.URL.Path {
		case "/ssl-vpn/prelogin.esp":
			encoded := base64.StdEncoding.EncodeToString([]byte(gatewayHTML))
			_, _ = response.Write(preloginResponse(encoded))
		case "/ssl-vpn/login.esp":
			loginForms <- parsedForm(t, request)
			response.WriteHeader(http.StatusInternalServerError)
			_, _ = response.Write([]byte(`<response><status>error</status></response>`))
		default:
			t.Fatalf("gateway path = %s, want prelogin or login", request.URL.Path)
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
			_, _ = response.Write([]byte(`<policy><gateways><external><list><entry name="` + gatewayServer.URL + `" /></list></external></gateways></policy>`))
		default:
			t.Fatalf("portal path = %s, want prelogin or config", request.URL.Path)
		}
	}))
	defer portalServer.Close()
	capturer := newGatewayFallbackAuthCapturer(
		gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: portalCookie},
		gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: gatewayCookie},
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	runner := app.NewRunner(app.IO{Stdout: &stdout, Stderr: &stderr, HTTPClient: portalServer.Client(), AuthCapturer: capturer})

	err := runner.Run(context.Background(), []string{
		"serve", "--listen", "127.0.0.1:0", "--portal", portalServer.URL,
		"--host-id", "test-host", "--browser", "chrome", "--timeout", "1s",
	})

	if !errors.Is(err, gp.ErrInvalidAuthArtifact) {
		t.Fatalf("Run() error = %v, want gateway retry failure", err)
	}
	wantEndpoints := []string{
		"portal:/global-protect/prelogin.esp",
		"portal:/global-protect/getconfig.esp",
		"gateway:/ssl-vpn/prelogin.esp",
		"gateway:/ssl-vpn/login.esp",
	}
	if got := endpoints.wait(t, len(wantEndpoints)); !slices.Equal(got, wantEndpoints) {
		t.Fatalf("endpoints = %#v, want %#v", got, wantEndpoints)
	}
	endpoints.assertIdle(t)
	form := waitForm(t, loginForms)
	if got := form.Get("prelogin-cookie"); got != "gateway-pre-cookie" {
		t.Fatalf("prelogin-cookie = %q, want gateway-pre-cookie", got)
	}
	if form.Get("portal-userauthcookie") != "empty" || form.Get("portal-prelogonuserauthcookie") != "empty" {
		t.Fatalf("portal cookie sentinels = %#v, want empty", form)
	}
	requests := capturer.waitRequests(t, 2)
	if requests[0].ProfileDir == "" || !filepath.IsAbs(requests[0].ProfileDir) || requests[1].ProfileDir != requests[0].ProfileDir {
		t.Fatalf("capture profile dirs = [%q, %q], want same absolute temp dir", requests[0].ProfileDir, requests[1].ProfileDir)
	}
	if _, statErr := os.Stat(requests[0].ProfileDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("temporary profile stat error = %v, want removed", statErr)
	}
}
