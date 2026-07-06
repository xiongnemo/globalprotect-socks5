package gp_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Client_Prelogin_postsGlobalProtectEndpoint_whenPortalProvided(t *testing.T) {
	// Given
	loginURL := "https://idp.example.test/login?SAMLRequest=abc"
	encoded := base64.StdEncoding.EncodeToString([]byte(loginURL))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/global-protect/prelogin.esp" {
			t.Fatalf("path = %s, want /global-protect/prelogin.esp", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.Form.Get("host-id") != "host-123" {
			t.Fatalf("host-id = %q, want host-123", r.Form.Get("host-id"))
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<prelogin-response><saml-auth-method>REDIRECT</saml-auth-method><saml-request>` + encoded + `</saml-request></prelogin-response>`))
	}))
	defer server.Close()

	portal, err := gp.NewPortalURL(server.URL)
	if err != nil {
		t.Fatalf("NewPortalURL() error = %v", err)
	}
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "host-123", Computer: "agent-test", ClientOS: gp.ClientOSLinux})

	// When
	got, err := client.Prelogin(context.Background(), portal)

	// Then
	if err != nil {
		t.Fatalf("Prelogin() error = %v", err)
	}
	if got.SAMLRequest.String() != loginURL {
		t.Fatalf("SAMLRequest = %q, want %q", got.SAMLRequest.String(), loginURL)
	}
}
