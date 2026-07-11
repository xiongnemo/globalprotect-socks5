package gp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_Client_GatewayConfig_sendsCookieSetByGatewayLogin_whenHTTPClientHasNoJar(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssl-vpn/login.esp":
			http.SetCookie(w, &http.Cookie{Name: "gateway-session", Value: "session-token", Path: "/"})
			_, _ = w.Write([]byte(`<jnlp><application-desc>` +
				`<argument></argument><argument>auth-cookie</argument><argument>persistent-cookie</argument>` +
				`<argument>vpn.example.test</argument><argument>alice@example.test</argument>` +
				`<argument>saml</argument><argument>config</argument><argument>EXAMPLE</argument>` +
				`<argument>unused</argument><argument>unused</argument><argument>test-host</argument>` +
				`<argument>unused</argument><argument>tunnel</argument><argument>-1</argument>` +
				`<argument>4100</argument></application-desc></jnlp>`))
		case "/ssl-vpn/getconfig.esp":
			cookie, err := r.Cookie("gateway-session")
			if err != nil || cookie.Value != "session-token" {
				w.WriteHeader(http.StatusOK)
				return
			}
			_, _ = w.Write([]byte(`<response status="success"><result>` +
				`<ip-address>10.41.0.12</ip-address>` +
				`<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>` +
				`</result></response>`))
		default:
			t.Fatalf("path = %s, want gateway login or config endpoint", r.URL.Path)
		}
	}))
	defer server.Close()
	gateway, err := NewPortalURL(server.URL)
	if err != nil {
		t.Fatalf("NewPortalURL() error = %v", err)
	}
	client := NewClient(server.Client(), ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: ClientOSLinux})
	artifact := AuthArtifact{Kind: ArtifactSAML, Username: "alice@example.test"}

	// When
	session, err := client.GatewayLogin(context.Background(), gateway, artifact)
	if err != nil {
		t.Fatalf("GatewayLogin() error = %v", err)
	}
	config, err := client.GatewayConfig(context.Background(), gateway, session)

	// Then
	if err != nil {
		t.Fatalf("GatewayConfig() error = %v", err)
	}
	if config.IP.String() != "10.41.0.12" {
		t.Fatalf("GatewayConfig() IP = %s, want 10.41.0.12", config.IP)
	}
}
