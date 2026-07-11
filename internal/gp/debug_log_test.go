package gp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func Test_Client_GatewayLogin_writesRedactedDebugEvent_whenGatewayRejectsLogin(t *testing.T) {
	// Given
	preloginCookie, err := NewSecret("pre-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(512)
		_, _ = w.Write([]byte(`<response><error>gateway rejected login</error><prelogin-cookie>pre-cookie</prelogin-cookie><saml-request>secret-saml-request</saml-request><input name="password" value="secret-password"><message>diagnostic</message></response>`))
	}))
	defer server.Close()
	portal := mustPortalURLInternal(t, server.URL)
	artifact := AuthArtifact{Kind: ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}
	var log bytes.Buffer
	client := NewClient(server.Client(), ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: ClientOSLinux}, WithDebugLog(&log))

	// When
	_, err = client.GatewayLogin(context.Background(), portal, artifact)

	// Then
	if !errors.Is(err, ErrInvalidAuthArtifact) {
		t.Fatalf("GatewayLogin() error = %v, want ErrInvalidAuthArtifact", err)
	}
	event := decodeDebugEvent(t, log.String())
	if event.Stage != "gateway_login" || event.Path != "/ssl-vpn/login.esp" || event.Method != http.MethodPost || event.Status != 512 {
		t.Fatalf("event = %#v, want gateway login POST 512", event)
	}
	if !slices.Contains(event.RequestFormFields, "prelogin-cookie") {
		t.Fatalf("request fields = %#v, want prelogin-cookie", event.RequestFormFields)
	}
	for _, secret := range []string{"pre-cookie", "secret-saml-request", "secret-password"} {
		if strings.Contains(event.ResponseSnippet, secret) || strings.Contains(log.String(), secret) {
			t.Fatalf("debug event leaked %q: %q", secret, log.String())
		}
	}
	if !strings.Contains(event.ResponseSnippet, "diagnostic") {
		t.Fatalf("response snippet = %q, want diagnostic text", event.ResponseSnippet)
	}
}

func Test_Client_GatewayLogin_omitsResponseSnippet_whenGatewayLoginSucceeds(t *testing.T) {
	// Given
	preloginCookie, err := NewSecret("pre-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<jnlp><application-desc>` +
			`<argument></argument>` +
			`<argument>auth-cookie-secret</argument>` +
			`<argument>persistent-cookie-secret</argument>` +
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
			`</application-desc></jnlp>`))
	}))
	defer server.Close()
	portal := mustPortalURLInternal(t, server.URL)
	artifact := AuthArtifact{Kind: ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}
	var log bytes.Buffer
	client := NewClient(server.Client(), ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: ClientOSLinux}, WithDebugLog(&log))

	// When
	session, err := client.GatewayLogin(context.Background(), portal, artifact)

	// Then
	if err != nil {
		t.Fatalf("GatewayLogin() error = %v", err)
	}
	if session.AuthCookie.String() != "auth-cookie-secret" {
		t.Fatalf("AuthCookie = %q, want auth-cookie-secret", session.AuthCookie.String())
	}
	event := decodeDebugEvent(t, log.String())
	if event.ResponseSnippet != "" {
		t.Fatalf("response snippet = %q, want empty for successful response", event.ResponseSnippet)
	}
	if strings.Contains(log.String(), "auth-cookie-secret") || strings.Contains(log.String(), "persistent-cookie-secret") {
		t.Fatalf("debug event leaked successful response secrets: %q", log.String())
	}
}

func Test_Client_PortalConfig_writesRedactedDebugEvent_whenPortalConfigRejected(t *testing.T) {
	// Given
	preloginCookie, err := NewSecret("pre-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(512)
		_, _ = w.Write([]byte(`<response><error>portal rejected config</error><portal-userauthcookie>portal-cookie</portal-userauthcookie><prelogin-cookie>pre-cookie</prelogin-cookie><message>diagnostic</message></response>`))
	}))
	defer server.Close()
	portal := mustPortalURLInternal(t, server.URL)
	artifact := AuthArtifact{Kind: ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}
	var log bytes.Buffer
	client := NewClient(server.Client(), ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: ClientOSLinux}, WithDebugLog(&log))

	// When
	_, err = client.PortalConfig(context.Background(), portal, artifact)

	// Then
	if !errors.Is(err, ErrInvalidAuthArtifact) {
		t.Fatalf("PortalConfig() error = %v, want ErrInvalidAuthArtifact", err)
	}
	event := decodeDebugEvent(t, log.String())
	if event.Stage != "portal_config" || event.Path != "/global-protect/getconfig.esp" || event.Method != http.MethodPost || event.Status != 512 {
		t.Fatalf("event = %#v, want portal config POST 512", event)
	}
	for _, field := range []string{"clientgpversion", "inputStr", "prelogin-cookie", "user"} {
		if !slices.Contains(event.RequestFormFields, field) {
			t.Fatalf("request fields = %#v, want %s", event.RequestFormFields, field)
		}
	}
	for _, secret := range []string{"pre-cookie", "portal-cookie"} {
		if strings.Contains(event.ResponseSnippet, secret) || strings.Contains(log.String(), secret) {
			t.Fatalf("debug event leaked %q: %q", secret, log.String())
		}
	}
	if !strings.Contains(event.ResponseSnippet, "diagnostic") {
		t.Fatalf("response snippet = %q, want diagnostic text", event.ResponseSnippet)
	}
}

func mustPortalURLInternal(t *testing.T, raw string) PortalURL {
	t.Helper()
	portal, err := NewPortalURL(raw)
	if err != nil {
		t.Fatalf("NewPortalURL() error = %v", err)
	}
	return portal
}

func decodeDebugEvent(t *testing.T, line string) debugHTTPEvent {
	t.Helper()
	var event debugHTTPEvent
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatalf("Unmarshal() error = %v; line=%q", err, line)
	}
	return event
}
