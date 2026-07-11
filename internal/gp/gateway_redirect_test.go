package gp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Client_GatewayLogin_doesNotReplaySecretForm_whenRedirected(t *testing.T) {
	// Given
	preloginCookie, err := gp.NewSecret("gateway-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	leakedBody := make(chan string, 1)
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		leakedBody <- string(body)
		_, _ = w.Write([]byte(`<jnlp><application-desc><argument></argument><argument>auth-cookie</argument><argument>persistent-cookie</argument><argument>vpn.example.test</argument><argument>alice@example.test</argument><argument>saml</argument><argument>config</argument><argument>EXAMPLE</argument><argument>unused</argument><argument>unused</argument><argument>test-host</argument><argument>unused</argument><argument>tunnel</argument><argument>-1</argument><argument>4100</argument></application-desc></jnlp>`))
	}))
	defer redirectTarget.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", redirectTarget.URL+"/steal")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})
	artifact := gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}

	// When
	_, err = client.GatewayLogin(context.Background(), mustPortalURL(t, server.URL), artifact)

	// Then
	if !errors.Is(err, gp.ErrInvalidAuthArtifact) {
		t.Fatalf("GatewayLogin() error = %v, want ErrInvalidAuthArtifact", err)
	}
	select {
	case body := <-leakedBody:
		t.Fatalf("redirect target received secret-bearing body: %q", body)
	default:
	}
}
