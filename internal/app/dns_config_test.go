package app

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func TestParseCLIInvocationReadsDNSOptions(t *testing.T) {
	cli, err := parseCLIInvocation([]string{
		"serve", "--dns-mode", "vpn", "--dns-servers", "10.0.0.53,10.0.0.54",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseCLIInvocation() error = %v", err)
	}
	assertOptionalString(t, cli.serve.DNSMode, "vpn")
	assertOptionalString(t, cli.serve.DNSServers, "10.0.0.53,10.0.0.54")
}

func TestParseServeDNSConfigParsesAndDeduplicatesIPv4Servers(t *testing.T) {
	patch := defaultsFor(commandServe).serve
	patch.DNSServers = presentString("10.0.0.53, 10.0.0.54;10.0.0.53")
	got, err := parseServeDNSConfig(patch)
	if err != nil {
		t.Fatalf("parseServeDNSConfig() error = %v", err)
	}
	want := []netip.Addr{netip.MustParseAddr("10.0.0.53"), netip.MustParseAddr("10.0.0.54")}
	if got.mode != serveDNSModeVPN || !reflect.DeepEqual(got.servers, want) {
		t.Fatalf("parseServeDNSConfig() = %#v, want vpn and %v", got, want)
	}
}

func TestParseServeDNSConfigRejectsUnsafeCombinations(t *testing.T) {
	tests := []struct {
		name, mode, servers string
		want                error
	}{
		{name: "mode", mode: "local", want: errInvalidDNSMode},
		{name: "system custom", mode: "system", servers: "10.0.0.53", want: errSystemCustomDNS},
		{name: "hostname", mode: "vpn", servers: "dns.example.test", want: errInvalidDNSServer},
		{name: "IPv6", mode: "vpn", servers: "2001:db8::53", want: errInvalidDNSServer},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			patch := defaultsFor(commandServe).serve
			patch.DNSMode = presentString(test.mode)
			patch.DNSServers = presentString(test.servers)
			_, err := parseServeDNSConfig(patch)
			if !errors.Is(err, test.want) {
				t.Fatalf("parseServeDNSConfig() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestEffectiveTunnelDNSUsesGatewayThenCustomOverride(t *testing.T) {
	config := gp.TunnelConfig{DNS: []netip.Addr{
		netip.MustParseAddr("10.0.0.53"), netip.MustParseAddr("2001:db8::53"),
	}}
	resolver, servers := effectiveTunnelDNS(serveTunnelOptions{dnsMode: serveDNSModeVPN}, config)
	if resolver != nil || !reflect.DeepEqual(servers, []netip.Addr{netip.MustParseAddr("10.0.0.53")}) {
		t.Fatalf("gateway DNS = (%v, %v), want nil resolver and IPv4 gateway DNS", resolver, servers)
	}

	custom := []netip.Addr{netip.MustParseAddr("10.1.0.53")}
	resolver, servers = effectiveTunnelDNS(serveTunnelOptions{dnsMode: serveDNSModeVPN, dnsServers: custom}, config)
	if resolver != nil || !reflect.DeepEqual(servers, custom) {
		t.Fatalf("custom DNS = (%v, %v), want nil resolver and %v", resolver, servers, custom)
	}
	servers[0] = netip.MustParseAddr("10.2.0.53")
	if custom[0] != netip.MustParseAddr("10.1.0.53") {
		t.Fatal("effectiveTunnelDNS() aliased caller-owned custom DNS slice")
	}
}

func TestEffectiveTunnelDNSSystemModeOptsOutExplicitly(t *testing.T) {
	resolver, servers := effectiveTunnelDNS(serveTunnelOptions{dnsMode: serveDNSModeSystem}, gp.TunnelConfig{})
	if resolver != net.DefaultResolver || servers != nil {
		t.Fatalf("system DNS = (%v, %v), want net.DefaultResolver and nil", resolver, servers)
	}
}

func TestMakeServeConfigRejectsCustomDNSWithoutPortal(t *testing.T) {
	patch := defaultsFor(commandServe).serve
	patch.DNSServers = presentString("10.0.0.53")
	if _, err := makeServeConfig(patch, false); err == nil {
		t.Fatal("makeServeConfig() error = nil, want custom DNS without portal rejection")
	}
}
