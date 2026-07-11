package gp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Client_GatewayLogin_returnsSession_whenGatewayAcceptsPreloginCookie(t *testing.T) {
	// Given
	preloginCookie, err := gp.NewSecret("pre-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	artifact := gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}
	var portal gp.PortalURL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ssl-vpn/login.esp" {
			t.Fatalf("path = %s, want /ssl-vpn/login.esp", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("prelogin-cookie"); got != "pre-cookie" {
			t.Fatalf("prelogin-cookie = %q, want pre-cookie", got)
		}
		if got := r.Form.Get("user"); got != "alice@example.test" {
			t.Fatalf("user = %q, want alice@example.test", got)
		}
		for field, want := range map[string]string{
			"server":                        portal.Hostname(),
			"host-id":                       "test-host",
			"os-version":                    "linux",
			"clientgpversion":               "4.1.0.98",
			"inputStr":                      "",
			"portal-prelogonuserauthcookie": "empty",
		} {
			if got := r.Form.Get(field); got != want {
				t.Fatalf("%s = %q, want %q", field, got, want)
			}
		}
		_, _ = w.Write([]byte(`<jnlp><application-desc>` +
			`<argument></argument>` +
			`<argument>auth-cookie</argument>` +
			`<argument>persistent-cookie</argument>` +
			`<argument>vpn.monashuniversity.cn</argument>` +
			`<argument>alice@example.test</argument>` +
			`<argument>saml</argument>` +
			`<argument>config</argument>` +
			`<argument>MONASH</argument>` +
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
	portal = mustPortalURL(t, server.URL)
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})

	// When
	session, err := client.GatewayLogin(context.Background(), portal, artifact)

	// Then
	if err != nil {
		t.Fatalf("GatewayLogin() error = %v", err)
	}
	if session.User != "alice@example.test" {
		t.Fatalf("User = %q, want alice@example.test", session.User)
	}
	if session.AuthCookie.String() != "auth-cookie" {
		t.Fatalf("AuthCookie = %q, want auth-cookie", session.AuthCookie.String())
	}
	if session.Domain != "MONASH" {
		t.Fatalf("Domain = %q, want MONASH", session.Domain)
	}
	if session.PreferredIP != "10.41.0.12" {
		t.Fatalf("PreferredIP = %q, want 10.41.0.12", session.PreferredIP)
	}
	if session.Computer != "gp-socks" {
		t.Fatalf("Computer = %q, want gp-socks", session.Computer)
	}
}

func Test_Client_GatewayLogin_normalizesAbsentPreferredIP(t *testing.T) {
	for _, absent := range []string{"", "(null)", "-1"} {
		t.Run(absent, func(t *testing.T) {
			// Given
			preloginCookie, err := gp.NewSecret("pre-cookie")
			if err != nil {
				t.Fatalf("NewSecret() error = %v", err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`<jnlp><application-desc>` +
					`<argument></argument><argument>auth-cookie</argument>` +
					`<argument></argument><argument>vpn.example.test</argument>` +
					`<argument>alice</argument><argument></argument><argument></argument>` +
					`<argument>DOMAIN</argument><argument></argument><argument></argument>` +
					`<argument>unreliable</argument><argument></argument><argument>tunnel</argument>` +
					`<argument>-1</argument><argument>4100</argument><argument>` + absent + `</argument>` +
					`</application-desc></jnlp>`))
			}))
			defer server.Close()
			client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})

			// When
			session, err := client.GatewayLogin(context.Background(), mustPortalURL(t, server.URL), gp.AuthArtifact{
				Kind: gp.ArtifactSAML, Username: "alice", PreloginCookie: preloginCookie,
			})

			// Then
			if err != nil {
				t.Fatalf("GatewayLogin() error = %v", err)
			}
			if session.PreferredIP != "" {
				t.Fatalf("PreferredIP = %q, want empty", session.PreferredIP)
			}
		})
	}
}
