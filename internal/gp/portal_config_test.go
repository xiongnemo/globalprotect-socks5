package gp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_ParsePortalConfig_returnsPortalCookieAndExternalGateways_whenPolicyListsGateways(t *testing.T) {
	// Given
	body := []byte(`<policy>` +
		`<portal-userauthcookie>portal-cookie</portal-userauthcookie>` +
		`<portal-prelogonuserauthcookie>prelogon-cookie</portal-prelogonuserauthcookie>` +
		`<gateways><external><list>` +
		`<entry name=" gw1.example.test "><description>Primary</description></entry>` +
		`<entry name="https://gw2.example.test"><description>Secondary</description></entry>` +
		`</list></external></gateways>` +
		`</policy>`)

	// When
	config, err := gp.ParsePortalConfig(body)

	// Then
	if err != nil {
		t.Fatalf("ParsePortalConfig() error = %v", err)
	}
	if config.PortalUserAuthCookie.String() != "portal-cookie" {
		t.Fatalf("PortalUserAuthCookie = %q, want portal-cookie", config.PortalUserAuthCookie.String())
	}
	if config.PortalPrelogonUserAuthCookie.String() != "prelogon-cookie" {
		t.Fatalf("PortalPrelogonUserAuthCookie = %q, want prelogon-cookie", config.PortalPrelogonUserAuthCookie.String())
	}
	if len(config.ExternalGateways) != 2 {
		t.Fatalf("ExternalGateways = %#v, want two gateways", config.ExternalGateways)
	}
	if config.ExternalGateways[0].Name != "gw1.example.test" || config.ExternalGateways[0].Description != "Primary" {
		t.Fatalf("first gateway = %#v, want trimmed primary gateway", config.ExternalGateways[0])
	}
	if config.ExternalGateways[1].Name != "https://gw2.example.test" {
		t.Fatalf("second gateway name = %q, want https://gw2.example.test", config.ExternalGateways[1].Name)
	}
}

func Test_Client_PortalConfig_postsGetConfigFields_whenPreloginCookieProvided(t *testing.T) {
	// Given
	preloginCookie, err := gp.NewSecret("pre-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	artifact := gp.AuthArtifact{
		Kind:                         gp.ArtifactSAML,
		Username:                     "alice@example.test",
		PreloginCookie:               preloginCookie,
		Token:                        mustSecret(t, "request-token"),
		PortalUserAuthCookie:         mustSecret(t, "request-user-cookie"),
		PortalPrelogonUserAuthCookie: mustSecret(t, "request-prelogon-cookie"),
	}
	var portal gp.PortalURL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/global-protect/getconfig.esp" {
			t.Fatalf("path = %s, want /global-protect/getconfig.esp", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("user"); got != "alice@example.test" {
			t.Fatalf("user = %q, want alice@example.test", got)
		}
		if got := r.Form.Get("passwd"); got != "" {
			t.Fatalf("passwd = %q, want blank with prelogin cookie", got)
		}
		for field, want := range map[string]string{
			"server":                        portal.Hostname(),
			"host":                          portal.Hostname(),
			"host-id":                       "test-host",
			"serialno":                      "test-host",
			"os-version":                    "linux",
			"clientgpversion":               "4.1.0.98",
			"portal-userauthcookie":         "request-user-cookie",
			"portal-prelogonuserauthcookie": "request-prelogon-cookie",
			"token":                         "request-token",
			"csc-digest":                    "",
			"config-digest":                 "",
			"swg-auth-token":                "0",
			"swg-nonce":                     "0",
		} {
			if got := r.Form.Get(field); got != want {
				t.Fatalf("%s = %q, want %q", field, got, want)
			}
		}
		for _, field := range []string{"clientVer", "clientgpversion", "clientos", "computer", "direct", "host", "host-id", "inputStr", "ipv6-support", "jnlpReady", "ok", "os-version", "portal-prelogonuserauthcookie", "portal-userauthcookie", "prelogin-cookie", "prot", "serialno", "server", "token"} {
			if !r.Form.Has(field) {
				t.Fatalf("form missing %s: %#v", field, r.Form)
			}
		}
		if got := r.Form.Get("prelogin-cookie"); got != "pre-cookie" {
			t.Fatalf("prelogin-cookie = %q, want pre-cookie", got)
		}
		_, _ = w.Write([]byte(`<policy>` +
			`<portal-userauthcookie>portal-cookie</portal-userauthcookie>` +
			`<portal-prelogonuserauthcookie>prelogon-cookie</portal-prelogonuserauthcookie>` +
			`<gateways><external><list><entry name="gw.example.test"><description>Gateway</description></entry></list></external></gateways>` +
			`</policy>`))
	}))
	defer server.Close()
	portal = mustPortalURL(t, server.URL)
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})

	// When
	config, err := client.PortalConfig(context.Background(), portal, artifact)

	// Then
	if err != nil {
		t.Fatalf("PortalConfig() error = %v", err)
	}
	if config.PortalUserAuthCookie.String() != "portal-cookie" {
		t.Fatalf("PortalUserAuthCookie = %q, want portal-cookie", config.PortalUserAuthCookie.String())
	}
	if config.PortalPrelogonUserAuthCookie.String() != "prelogon-cookie" {
		t.Fatalf("PortalPrelogonUserAuthCookie = %q, want prelogon-cookie", config.PortalPrelogonUserAuthCookie.String())
	}
	if len(config.ExternalGateways) != 1 || config.ExternalGateways[0].Name != "gw.example.test" {
		t.Fatalf("ExternalGateways = %#v, want gw.example.test", config.ExternalGateways)
	}
}

func Test_ParsePortalConfig_mergesNestedPolicyCookiesWithRootGateways(t *testing.T) {
	// Given
	body := []byte(`<response><policy>` +
		`<portal-userauthcookie>nested-user-cookie</portal-userauthcookie>` +
		`<portal-prelogonuserauthcookie>nested-prelogon-cookie</portal-prelogonuserauthcookie>` +
		`</policy><gateways><external><list><entry name="gw.example.test"/></list></external></gateways></response>`)

	// When
	config, err := gp.ParsePortalConfig(body)

	// Then
	if err != nil {
		t.Fatalf("ParsePortalConfig() error = %v", err)
	}
	if config.PortalUserAuthCookie.String() != "nested-user-cookie" ||
		config.PortalPrelogonUserAuthCookie.String() != "nested-prelogon-cookie" {
		t.Fatalf("portal cookies = (%q, %q), want nested policy cookies",
			config.PortalUserAuthCookie.String(), config.PortalPrelogonUserAuthCookie.String())
	}
	if len(config.ExternalGateways) != 1 || config.ExternalGateways[0].Name != "gw.example.test" {
		t.Fatalf("ExternalGateways = %#v, want root gateway", config.ExternalGateways)
	}
}

func Test_ParsePortalConfig_allowsGatewaySAML_whenPortalCookiesAreAbsent(t *testing.T) {
	// When
	config, err := gp.ParsePortalConfig([]byte(`<policy><gateways><external><list>` +
		`<entry name="gw.example.test"/></list></external></gateways></policy>`))

	// Then
	if err != nil {
		t.Fatalf("ParsePortalConfig() error = %v", err)
	}
	if config.PortalUserAuthCookie.String() != "" || config.PortalPrelogonUserAuthCookie.String() != "" {
		t.Fatalf("portal cookies = (%q, %q), want absent",
			config.PortalUserAuthCookie.String(), config.PortalPrelogonUserAuthCookie.String())
	}
}
