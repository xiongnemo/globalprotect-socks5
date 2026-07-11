package gp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Client_GatewayLogin_rejectsMalformedSessionArguments(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
	}{
		{name: "truncated", arguments: validGatewayArguments()[:14]},
		{name: "empty auth cookie", arguments: replaceGatewayArgument(1, "")},
		{name: "null auth cookie", arguments: replaceGatewayArgument(1, "(null)")},
		{name: "rejected auth cookie", arguments: replaceGatewayArgument(1, "-1")},
		{name: "empty user", arguments: replaceGatewayArgument(4, "")},
		{name: "null user", arguments: replaceGatewayArgument(4, "(null)")},
		{name: "rejected user", arguments: replaceGatewayArgument(4, "-1")},
		{name: "wrong connection type", arguments: replaceGatewayArgument(12, "prelogon")},
		{name: "wrong client version", arguments: replaceGatewayArgument(14, "4200")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			server := gatewayLoginServer(t, test.arguments)
			defer server.Close()
			client := gp.NewClient(server.Client(), gp.ClientProfile{Computer: "gp-socks", ClientOS: gp.ClientOSLinux})

			// When
			_, err := client.GatewayLogin(context.Background(), mustPortalURL(t, server.URL), gp.AuthArtifact{})

			// Then
			if err == nil {
				t.Fatal("GatewayLogin() error = nil, want malformed session error")
			}
		})
	}
}

func validGatewayArguments() []string {
	return []string{"", "auth-cookie", "persistent-cookie", "vpn.example.test", "alice", "saml", "config", "DOMAIN", "", "", "host", "", "tunnel", "-1", "4100", "10.0.0.2"}
}

func replaceGatewayArgument(index int, value string) []string {
	arguments := validGatewayArguments()
	arguments[index] = value
	return arguments
}

func gatewayLoginServer(t *testing.T, arguments []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var body strings.Builder
		body.WriteString(`<jnlp><application-desc>`)
		for _, argument := range arguments {
			body.WriteString(`<argument>`)
			body.WriteString(argument)
			body.WriteString(`</argument>`)
		}
		body.WriteString(`</application-desc></jnlp>`)
		_, _ = w.Write([]byte(body.String()))
	}))
}
