package gp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Client_GatewayLogin_forwardsPortalAuthCookiesAndContext(t *testing.T) {
	tests := []struct {
		name           string
		userCookie     gp.Secret
		prelogonCookie gp.Secret
		wantUser       string
	}{
		{name: "both cookies", userCookie: mustSecret(t, "user-cookie"), prelogonCookie: mustSecret(t, "prelogon-cookie"), wantUser: "user-cookie"},
		{name: "prelogon cookie only", prelogonCookie: mustSecret(t, "prelogon-cookie"), wantUser: "empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Fatalf("ParseForm() error = %v", err)
				}
				gatewayHost, _, _ := strings.Cut(r.Host, ":")
				for field, want := range map[string]string{
					"portal-userauthcookie":         test.wantUser,
					"portal-prelogonuserauthcookie": "prelogon-cookie",
					"prelogin-cookie":               "",
					"token":                         "",
					"host":                          gatewayHost,
					"gw":                            gatewayHost,
					"gateway-name":                  gatewayHost,
				} {
					if got := r.Form.Get(field); got != want {
						t.Fatalf("%s = %q, want %q", field, got, want)
					}
				}
				var body strings.Builder
				body.WriteString(`<jnlp><application-desc>`)
				for _, argument := range validGatewayArguments() {
					body.WriteString(`<argument>` + argument + `</argument>`)
				}
				body.WriteString(`</application-desc></jnlp>`)
				_, _ = w.Write([]byte(body.String()))
			}))
			defer server.Close()
			client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})

			_, err := client.GatewayLogin(context.Background(), mustPortalURL(t, server.URL), gp.AuthArtifact{
				Kind:                         gp.ArtifactSAML,
				Username:                     "alice",
				PortalUserAuthCookie:         test.userCookie,
				PortalPrelogonUserAuthCookie: test.prelogonCookie,
			})
			if err != nil {
				t.Fatalf("GatewayLogin() error = %v", err)
			}
		})
	}
}
