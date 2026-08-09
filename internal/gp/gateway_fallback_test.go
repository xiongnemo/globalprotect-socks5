package gp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Client_GatewayLogin_returnsGatewayAuthFailed_whenPortalCookieRejectedWith512(t *testing.T) {
	// Given
	portalCookie, err := gp.NewSecret("portal-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	artifact := gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PortalUserAuthCookie: portalCookie}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ssl-vpn/login.esp" {
			t.Fatalf("path = %s, want /ssl-vpn/login.esp", r.URL.Path)
		}
		w.WriteHeader(512)
		_, _ = w.Write([]byte(`<response><status>auth-failed</status><msg>gateway rejected portal cookie</msg></response>`))
	}))
	defer server.Close()
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})

	// When
	_, err = client.GatewayLogin(context.Background(), mustPortalURL(t, server.URL), artifact)

	// Then
	if !errors.Is(err, gp.ErrInvalidAuthArtifact) {
		t.Fatalf("GatewayLogin() error = %v, want ErrInvalidAuthArtifact", err)
	}
	if !errors.Is(err, gp.ErrGatewayAuthFailed) {
		t.Fatalf("GatewayLogin() error = %v, want ErrGatewayAuthFailed", err)
	}
	var authErr *gp.GatewayAuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("GatewayLogin() error = %T, want GatewayAuthError", err)
	}
	if authErr.StatusCode != 512 {
		t.Fatalf("StatusCode = %d, want 512", authErr.StatusCode)
	}
}

func Test_Client_GatewayPrelogin_postsGatewayEndpointAndParsesSAML(t *testing.T) {
	// Given
	loginURL := "https://idp.example.test/gateway-login?SAMLRequest=gateway"
	encoded := base64.StdEncoding.EncodeToString([]byte(loginURL))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/ssl-vpn/prelogin.esp" {
			t.Fatalf("path = %s, want /ssl-vpn/prelogin.esp", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("host-id"); got != "test-host" {
			t.Fatalf("host-id = %q, want test-host", got)
		}
		_, _ = w.Write([]byte(`<prelogin-response><saml-auth-method>REDIRECT</saml-auth-method><saml-request>` + encoded + `</saml-request><saml-default-browser>yes</saml-default-browser><region>AU</region></prelogin-response>`))
	}))
	defer server.Close()
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})

	// When
	prelogin, err := client.GatewayPrelogin(context.Background(), mustPortalURL(t, server.URL))

	// Then
	if err != nil {
		t.Fatalf("GatewayPrelogin() error = %v", err)
	}
	if prelogin.AuthMode != gp.AuthModeSAML {
		t.Fatalf("AuthMode = %q, want %q", prelogin.AuthMode, gp.AuthModeSAML)
	}
	if prelogin.SAMLRequest.String() != loginURL {
		t.Fatalf("SAMLRequest = %q, want %q", prelogin.SAMLRequest.String(), loginURL)
	}
	if !prelogin.DefaultBrowser {
		t.Fatal("DefaultBrowser = false, want true")
	}
}

func Test_Client_GatewayLogin_usesPreloginCookieAndEmptyPortalSentinels_whenGatewayCookieSupplied(t *testing.T) {
	// Given
	preloginCookie, err := gp.NewSecret("gateway-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	artifact := gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("prelogin-cookie"); got != "gateway-cookie" {
			t.Fatalf("prelogin-cookie = %q, want gateway-cookie", got)
		}
		for _, field := range []string{"portal-userauthcookie", "portal-prelogonuserauthcookie"} {
			if got := r.Form.Get(field); got != "empty" {
				t.Fatalf("%s = %q, want empty sentinel", field, got)
			}
		}
		_, _ = w.Write([]byte(`<jnlp><application-desc>` +
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
			`</application-desc></jnlp>`))
	}))
	defer server.Close()
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})

	// When
	session, err := client.GatewayLogin(context.Background(), mustPortalURL(t, server.URL), artifact)

	// Then
	if err != nil {
		t.Fatalf("GatewayLogin() error = %v", err)
	}
	if session.AuthCookie.String() != "auth-cookie" {
		t.Fatalf("AuthCookie = %q, want auth-cookie", session.AuthCookie.String())
	}
}

func Test_Client_GatewayFallbackDebugEvents_areOrderedAndRedacted(t *testing.T) {
	// Given
	gatewayCookie, err := gp.NewSecret("gateway-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	loginURL := "https://idp.example.test/secret-saml-login"
	encoded := base64.StdEncoding.EncodeToString([]byte(loginURL))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssl-vpn/prelogin.esp":
			_, _ = w.Write([]byte(`<prelogin-response><saml-auth-method>REDIRECT</saml-auth-method><saml-request>` + encoded + `</saml-request></prelogin-response>`))
		case "/ssl-vpn/login.esp":
			w.WriteHeader(512)
			_, _ = w.Write([]byte(`<response><status>auth-failed</status><prelogin-cookie>gateway-cookie</prelogin-cookie><saml-request>secret-saml</saml-request><msg>retry needed</msg></response>`))
		default:
			t.Fatalf("path = %s, want gateway fallback endpoint", r.URL.Path)
		}
	}))
	defer server.Close()
	var log bytes.Buffer
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux}, gp.WithDebugLog(&log))

	// When
	_, preloginErr := client.GatewayPrelogin(context.Background(), mustPortalURL(t, server.URL))
	_, loginErr := client.GatewayLogin(context.Background(), mustPortalURL(t, server.URL), gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: gatewayCookie})

	// Then
	if preloginErr != nil {
		t.Fatalf("GatewayPrelogin() error = %v", preloginErr)
	}
	if !errors.Is(loginErr, gp.ErrGatewayAuthFailed) {
		t.Fatalf("GatewayLogin() error = %v, want ErrGatewayAuthFailed", loginErr)
	}
	decoder := json.NewDecoder(bytes.NewReader(log.Bytes()))
	var events []struct {
		Stage             string   `json:"stage"`
		Path              string   `json:"path"`
		RequestFormFields []string `json:"request_form_fields"`
		Status            int      `json:"status"`
	}
	for decoder.More() {
		var event struct {
			Stage             string   `json:"stage"`
			Path              string   `json:"path"`
			RequestFormFields []string `json:"request_form_fields"`
			Status            int      `json:"status"`
		}
		if err := decoder.Decode(&event); err != nil {
			t.Fatalf("Decode() error = %v; data=%q", err, log.String())
		}
		events = append(events, event)
	}
	if len(events) != 2 {
		t.Fatalf("events = %#v, want gateway_prelogin then gateway_login", events)
	}
	if events[0].Stage != "gateway_prelogin" || events[0].Status != http.StatusOK || events[0].Path != "/ssl-vpn/prelogin.esp" {
		t.Fatalf("first event = %#v, want gateway_prelogin 200", events[0])
	}
	if events[1].Stage != "gateway_login" || events[1].Status != 512 || events[1].Path != "/ssl-vpn/login.esp" {
		t.Fatalf("second event = %#v, want gateway_login 512", events[1])
	}
	if !slices.Contains(events[1].RequestFormFields, "prelogin-cookie") {
		t.Fatalf("gateway login fields = %#v, want prelogin-cookie", events[1].RequestFormFields)
	}
	for _, secret := range []string{"gateway-cookie", "secret-saml", encoded, loginURL} {
		if strings.Contains(log.String(), secret) {
			t.Fatalf("debug log leaked %q: %q", secret, log.String())
		}
	}
}
