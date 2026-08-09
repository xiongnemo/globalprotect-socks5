package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func TestRunner_gatewayLoginWithFallbackAcceptsPrelogonOnlyCookieWithPasswordPrelogin(t *testing.T) {
	endpoints := make(chan string, 2)
	loginForms := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		endpoints <- request.URL.Path
		switch request.URL.Path {
		case "/ssl-vpn/prelogin.esp":
			_, _ = response.Write([]byte(`<prelogin-response><auth-method>password</auth-method></prelogin-response>`))
		case "/ssl-vpn/login.esp":
			if err := request.ParseForm(); err != nil {
				t.Errorf("ParseForm() error = %v", err)
				return
			}
			loginForms <- request.Form
			_, _ = response.Write(testGatewayLoginResponse())
		default:
			t.Errorf("unexpected gateway path %s", request.URL.Path)
		}
	}))
	defer server.Close()
	prelogonCookie := testAppSecret(t, "prelogon-cookie")
	client, gateway := testGatewayClient(t, server)

	session, err := (Runner{}).gatewayLoginWithFallback(context.Background(), gatewayLoginRequest{
		client: client, gateway: gateway,
		artifact: gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PortalPrelogonUserAuthCookie: prelogonCookie},
	}, newDefaultAppLogger(io.Discard))

	if err != nil {
		t.Fatalf("gatewayLoginWithFallback() error = %v", err)
	}
	if session.User != "alice@example.test" {
		t.Fatalf("session user = %q, want alice@example.test", session.User)
	}
	gotEndpoints := []string{<-endpoints, <-endpoints}
	if !slices.Equal(gotEndpoints, []string{"/ssl-vpn/prelogin.esp", "/ssl-vpn/login.esp"}) {
		t.Fatalf("endpoints = %#v, want prelogin then login", gotEndpoints)
	}
	loginForm := <-loginForms
	if loginForm.Get("portal-prelogonuserauthcookie") != "prelogon-cookie" || loginForm.Get("portal-userauthcookie") != "empty" {
		t.Fatalf("portal cookie form = %#v, want prelogon-only credential", loginForm)
	}
}

func TestRunner_gatewayLoginWithFallbackDoesNotLoginWhenGatewayPreloginFails(t *testing.T) {
	var loginCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/ssl-vpn/login.esp" {
			loginCalls.Add(1)
		}
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	portalCookie := testAppSecret(t, "portal-cookie")
	client, gateway := testGatewayClient(t, server)

	_, err := (Runner{}).gatewayLoginWithFallback(context.Background(), gatewayLoginRequest{
		client: client, gateway: gateway,
		artifact: gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PortalUserAuthCookie: portalCookie},
	}, newDefaultAppLogger(io.Discard))

	if err == nil || !errors.Is(err, gp.ErrInvalidAuthArtifact) {
		t.Fatalf("gatewayLoginWithFallback() error = %v, want prelogin failure", err)
	}
	if loginCalls.Load() != 0 {
		t.Fatalf("gateway login calls = %d, want 0", loginCalls.Load())
	}
}

func testGatewayClient(t *testing.T, server *httptest.Server) (gp.Client, gp.PortalURL) {
	t.Helper()
	gateway, err := gp.NewPortalURL(server.URL)
	if err != nil {
		t.Fatalf("NewPortalURL() error = %v", err)
	}
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})
	return client, gateway
}

func testAppSecret(t *testing.T, raw string) gp.Secret {
	t.Helper()
	secret, err := gp.NewSecret(raw)
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	return secret
}

func testGatewayLoginResponse() []byte {
	return []byte(`<jnlp><application-desc><argument></argument><argument>auth-cookie</argument>` +
		`<argument>persistent-cookie</argument><argument>vpn.example.test</argument><argument>alice@example.test</argument>` +
		`<argument>saml</argument><argument>config</argument><argument>EXAMPLE</argument><argument>unused</argument>` +
		`<argument>unused</argument><argument>test-host</argument><argument>unused</argument><argument>tunnel</argument>` +
		`<argument>-1</argument><argument>4100</argument><argument>10.41.0.12</argument></application-desc></jnlp>`)
}
