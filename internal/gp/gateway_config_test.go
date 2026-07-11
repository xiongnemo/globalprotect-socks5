package gp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Client_GatewayConfig_returnsTunnelConfig_whenGatewayProvidesSSLConfig(t *testing.T) {
	// Given
	authCookie, err := gp.NewSecret("auth-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	session := gp.GatewaySession{AuthCookie: authCookie, User: "alice@example.test", Portal: "vpn.monashuniversity.cn", Domain: "MONASH", Computer: "gp-socks", PreferredIP: "10.41.0.12"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ssl-vpn/getconfig.esp" {
			t.Fatalf("path = %s, want /ssl-vpn/getconfig.esp", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		for field, want := range map[string]string{
			"client-type":      "1",
			"protocol-version": "p1",
			"internal":         "no",
			"app-version":      "5.1.5-8",
			"ipv6-support":     "no",
			"clientos":         "Linux",
			"os-version":       "linux",
			"hmac-algo":        "sha1,md5,sha256",
			"enc-algo":         "aes-128-cbc,aes-256-cbc",
			"authcookie":       "auth-cookie",
			"portal":           "vpn.monashuniversity.cn",
			"user":             "alice@example.test",
			"domain":           "MONASH",
			"computer":         "gp-socks",
			"preferred-ip":     "10.41.0.12",
		} {
			if got := r.Form.Get(field); got != want {
				t.Errorf("%s = %q, want %q", field, got, want)
			}
		}
		if r.Form.Has("preferred-ipv6") {
			t.Error("preferred-ipv6 is present, want absent")
		}
		_, _ = w.Write([]byte(`<response status="success"><result>` +
			`<ip-address>10.41.0.12</ip-address>` +
			`<netmask>255.255.255.255</netmask>` +
			`<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>` +
			`<dns><member>10.41.0.1</member><member>10.41.0.2</member></dns>` +
			`<access-routes><member>10.0.0.0/8</member></access-routes>` +
			`<exclude-access-routes><member>10.99.0.0/16</member></exclude-access-routes>` +
			`</result></response>`))
	}))
	defer server.Close()
	portal := mustPortalURL(t, server.URL)
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})

	// When
	config, err := client.GatewayConfig(context.Background(), portal, session)

	// Then
	if err != nil {
		t.Fatalf("GatewayConfig() error = %v", err)
	}
	if config.IP.String() != "10.41.0.12" {
		t.Fatalf("IP = %s, want 10.41.0.12", config.IP)
	}
	if config.SSLTunnelURL != "/ssl-tunnel-connect.sslvpn" {
		t.Fatalf("SSLTunnelURL = %q, want /ssl-tunnel-connect.sslvpn", config.SSLTunnelURL)
	}
	if len(config.DNS) != 2 || config.DNS[0].String() != "10.41.0.1" {
		t.Fatalf("DNS = %#v, want two DNS servers", config.DNS)
	}
	if len(config.IncludeRoutes) != 1 || config.IncludeRoutes[0].String() != "10.0.0.0/8" {
		t.Fatalf("IncludeRoutes = %#v, want 10.0.0.0/8", config.IncludeRoutes)
	}
	if len(config.ExcludeRoutes) != 1 || config.ExcludeRoutes[0].String() != "10.99.0.0/16" {
		t.Fatalf("ExcludeRoutes = %#v, want 10.99.0.0/16", config.ExcludeRoutes)
	}
}

func Test_Client_GatewayConfig_returnsTunnelConfig_whenGatewayProvidesDirectSSLConfig(t *testing.T) {
	// Given
	authCookie, err := gp.NewSecret("auth-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	session := gp.GatewaySession{AuthCookie: authCookie, User: "alice@example.test", Portal: "vpn.monashuniversity.cn", Domain: "MONASH"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<response status="success">` +
			`<ip-address>10.41.0.12</ip-address>` +
			`<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>` +
			`<dns><member>10.41.0.1</member></dns>` +
			`<access-routes><member>10.0.0.0/8</member></access-routes>` +
			`</response>`))
	}))
	defer server.Close()
	portal := mustPortalURL(t, server.URL)
	client := gp.NewClient(server.Client(), gp.ClientProfile{HostID: "test-host", Computer: "gp-socks", ClientOS: gp.ClientOSLinux})

	// When
	config, err := client.GatewayConfig(context.Background(), portal, session)

	// Then
	if err != nil {
		t.Fatalf("GatewayConfig() error = %v", err)
	}
	if config.IP.String() != "10.41.0.12" {
		t.Fatalf("IP = %s, want 10.41.0.12", config.IP)
	}
	if config.SSLTunnelURL != "/ssl-tunnel-connect.sslvpn" {
		t.Fatalf("SSLTunnelURL = %q, want /ssl-tunnel-connect.sslvpn", config.SSLTunnelURL)
	}
	if len(config.IncludeRoutes) != 1 || config.IncludeRoutes[0].String() != "10.0.0.0/8" {
		t.Fatalf("IncludeRoutes = %#v, want 10.0.0.0/8", config.IncludeRoutes)
	}
}
