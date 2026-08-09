package app

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
)

func TestParseCLIInvocation_readsSOCKSOptionsAndNonLoopbackOptIn(t *testing.T) {
	const password = "CLI_PASSWORD_CANARY"
	cli, err := parseCLIInvocation([]string{
		"serve", "--listen", "0.0.0.0:1080", "--allow-non-loopback",
		"--socks-username", "cli-user", "--socks-password", password,
		"--handshake-timeout", "12s", "--connect-timeout", "34s", "--max-connections", "345",
	}, &bytes.Buffer{})
	if err != nil {
		if strings.Contains(err.Error(), password) {
			t.Fatal("CLI parse error leaked SOCKS password")
		}
		t.Fatal("parseCLIInvocation() returned an unexpected error")
	}
	if !cli.allowNonLoopback {
		t.Fatal("allowNonLoopback = false, want true")
	}
	assertOptionalString(t, cli.serve.SOCKSUsername, "cli-user")
	if !cli.serve.SOCKSPassword.present || cli.serve.SOCKSPassword.value != password {
		t.Fatal("CLI SOCKS password was not captured")
	}
	assertOptionalString(t, cli.serve.HandshakeTimeout, "12s")
	assertOptionalString(t, cli.serve.ConnectTimeout, "34s")
	assertOptionalString(t, cli.serve.MaxConnections, "345")
}

func TestMakeServeConfig_appliesSOCKSDefaults(t *testing.T) {
	config, err := makeServeConfig(defaultsFor(commandServe).serve, false)
	if err != nil {
		t.Fatalf("makeServeConfig() error = %v", err)
	}
	if config.socksCredentials != nil {
		t.Fatal("default SOCKS credentials are enabled")
	}
	if config.handshakeTimeout != 10*time.Second || config.connectTimeout != 30*time.Second {
		t.Fatalf("SOCKS timeouts = (%s, %s), want (10s, 30s)", config.handshakeTimeout, config.connectTimeout)
	}
	if config.maxConnections != 256 {
		t.Fatalf("max connections = %d, want 256", config.maxConnections)
	}
}

func TestMakeServeConfig_acceptsAuthenticatedNonLoopbackOptIn(t *testing.T) {
	const password = "NON_LOOPBACK_PASSWORD_CANARY"
	patch := defaultsFor(commandServe).serve
	patch.Listen = testOptionalString("0.0.0.0:1080")
	patch.SOCKSUsername = testOptionalString("proxy-user")
	patch.SOCKSPassword = testOptionalString(password)
	patch.HandshakeTimeout = testOptionalString("12s")
	patch.ConnectTimeout = testOptionalString("34s")
	patch.MaxConnections = testOptionalString("345")
	config, err := makeServeConfig(patch, true)
	if err != nil {
		if strings.Contains(err.Error(), password) {
			t.Fatal("configuration error leaked SOCKS password")
		}
		t.Fatal("makeServeConfig() returned an unexpected error")
	}
	if config.socksCredentials == nil || config.socksCredentials.Username != "proxy-user" {
		t.Fatal("SOCKS credentials were not configured")
	}
	if config.socksCredentials.Password != password {
		t.Fatal("SOCKS password was not preserved")
	}
	if config.handshakeTimeout != 12*time.Second || config.connectTimeout != 34*time.Second || config.maxConnections != 345 {
		t.Fatal("explicit SOCKS limits were not preserved")
	}
}

func TestMakeServeConfig_rejectsUnsafeOrInvalidSOCKSConfigurationWithoutLeakingPassword(t *testing.T) {
	const password = "PASSWORD_CANARY_8CF29"
	tests := []struct {
		name   string
		mutate func(*servePatch)
		allow  bool
	}{
		{name: "non-loopback without opt-in", mutate: func(p *servePatch) {
			p.Listen = testOptionalString("0.0.0.0:1080")
			p.SOCKSUsername, p.SOCKSPassword = testOptionalString("user"), testOptionalString(password)
		}},
		{name: "non-loopback without authentication", allow: true, mutate: func(p *servePatch) {
			p.Listen = testOptionalString("0.0.0.0:1080")
		}},
		{name: "partial credentials", mutate: func(p *servePatch) {
			p.SOCKSPassword = testOptionalString(password)
		}},
		{name: "oversized password", mutate: func(p *servePatch) {
			p.SOCKSUsername = testOptionalString("user")
			p.SOCKSPassword = testOptionalString(password + strings.Repeat("x", 256))
		}},
		{name: "zero handshake timeout", mutate: func(p *servePatch) {
			p.HandshakeTimeout = testOptionalString("0s")
		}},
		{name: "zero connection limit", mutate: func(p *servePatch) {
			p.MaxConnections = testOptionalString("0")
		}},
		{name: "excessive connection limit", mutate: func(p *servePatch) {
			p.MaxConnections = testOptionalString("65536")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			patch := defaultsFor(commandServe).serve
			test.mutate(&patch)
			_, err := makeServeConfig(patch, test.allow)
			if err == nil {
				t.Fatal("makeServeConfig() error = nil, want rejection")
			}
			if strings.Contains(err.Error(), password) {
				t.Fatal("configuration error leaked SOCKS password")
			}
		})
	}
}

func TestValidateListenPolicy_allowsOnlyLoopbackByDefault(t *testing.T) {
	credentials := &socks5.Credentials{Username: "user", Password: "password"}
	tests := []struct {
		name        string
		address     string
		allow       bool
		credentials *socks5.Credentials
		wantErr     bool
	}{
		{name: "IPv4 loopback", address: "127.0.0.1:1080"},
		{name: "IPv4 loopback range", address: "127.10.20.30:1080"},
		{name: "IPv6 loopback", address: "[::1]:1080"},
		{name: "localhost", address: "localhost:1080"},
		{name: "IPv4 wildcard", address: "0.0.0.0:1080", wantErr: true},
		{name: "IPv6 wildcard", address: "[::]:1080", wantErr: true},
		{name: "LAN address", address: "192.0.2.10:1080", wantErr: true},
		{name: "opt-in without auth", address: "0.0.0.0:1080", allow: true, wantErr: true},
		{name: "authenticated opt-in", address: "0.0.0.0:1080", allow: true, credentials: credentials},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateListenPolicy(test.address, test.allow, test.credentials)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateListenPolicy() error present = %t, want %t", err != nil, test.wantErr)
			}
		})
	}
}

func TestValidateBoundListenAddress_rechecksActualAddress(t *testing.T) {
	credentials := &socks5.Credentials{Username: "user", Password: "password"}
	loopback := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}
	wildcard := &net.TCPAddr{IP: net.IPv4zero, Port: 1080}
	if err := validateBoundListenAddress(loopback, false, nil); err != nil {
		t.Fatalf("loopback validation error = %v", err)
	}
	if err := validateBoundListenAddress(wildcard, false, credentials); err == nil {
		t.Fatal("wildcard validation error = nil without opt-in")
	}
	if err := validateBoundListenAddress(wildcard, true, credentials); err != nil {
		t.Fatalf("authenticated wildcard validation error = %v", err)
	}
}

func TestNonLoopbackOptIn_isNotAcceptedFromYAMLOrEnvironment(t *testing.T) {
	if _, err := decodeConfig(strings.NewReader("serve:\n  allow_non_loopback: \"true\"\n")); err == nil {
		t.Fatal("decodeConfig() accepted allow_non_loopback")
	}
	file := fileConfig{Serve: servePatch{
		Listen:        testOptionalString("0.0.0.0:1080"),
		SOCKSUsername: testOptionalString("user"), SOCKSPassword: testOptionalString("password"),
	}}
	raw, err := resolveRawInvocation(cliInvocation{command: commandServe}, file, testLookupEnv(map[string]string{
		"GP_SOCKS_ALLOW_NON_LOOPBACK": "true",
	}))
	if err != nil {
		t.Fatalf("resolveRawInvocation() error = %v", err)
	}
	if raw.allowNonLoopback {
		t.Fatal("environment enabled non-loopback opt-in")
	}
	if _, err := makeServeConfig(raw.serve, raw.allowNonLoopback); err == nil {
		t.Fatal("environment-only non-loopback configuration was accepted")
	}
}
