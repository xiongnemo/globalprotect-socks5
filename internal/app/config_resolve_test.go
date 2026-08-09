package app

import (
	"testing"
)

func TestDefaultsFor_probeMatchesExistingCommandDefaults(t *testing.T) {
	// Given
	command := commandName("probe")

	// When
	got := defaultsFor(command)

	// Then
	assertOptionalString(t, got.logLevel, "error")
	assertOptionalString(t, got.probe.Portal, "")
	assertOptionalString(t, got.probe.HostID, "gp-socks")
	assertOptionalString(t, got.probe.SSOFile, "")
	assertOptionalString(t, got.probe.DebugLog, "")
}

func TestDefaultsFor_authMatchesExistingCommandDefaults(t *testing.T) {
	// Given
	command := commandName("auth")

	// When
	got := defaultsFor(command)

	// Then
	assertOptionalString(t, got.logLevel, "error")
	assertOptionalString(t, got.auth.Portal, "")
	assertOptionalString(t, got.auth.HostID, "gp-socks")
	assertOptionalString(t, got.auth.Browser, "auto")
	assertOptionalString(t, got.auth.BrowserPath, "")
	assertOptionalString(t, got.auth.BrowserProfileDir, "")
	assertOptionalString(t, got.auth.Timeout, "5m")
	assertOptionalString(t, got.auth.DebugLog, "")
}

func TestDefaultsFor_serveMatchesExistingCommandDefaults(t *testing.T) {
	// Given
	command := commandName("serve")

	// When
	got := defaultsFor(command)

	// Then
	assertOptionalString(t, got.logLevel, "error")
	assertOptionalString(t, got.serve.Listen, "127.0.0.1:1080")
	assertOptionalString(t, got.serve.SOCKSUsername, "")
	assertOptionalString(t, got.serve.SOCKSPassword, "")
	assertOptionalString(t, got.serve.HandshakeTimeout, "10s")
	assertOptionalString(t, got.serve.ConnectTimeout, "30s")
	assertOptionalString(t, got.serve.MaxConnections, "256")
	assertOptionalString(t, got.serve.Portal, "")
	assertOptionalString(t, got.serve.Gateway, "")
	assertOptionalString(t, got.serve.DNSMode, "vpn")
	assertOptionalString(t, got.serve.DNSServers, "")
	assertOptionalString(t, got.serve.HostID, "gp-socks")
	assertOptionalString(t, got.serve.Browser, "auto")
	assertOptionalString(t, got.serve.BrowserPath, "")
	assertOptionalString(t, got.serve.BrowserProfileDir, "")
	assertOptionalString(t, got.serve.Timeout, "5m")
	assertOptionalString(t, got.serve.DebugLog, "")
}

func TestDefaultsFor_parseAuthIncludesOnlyRootDefaults(t *testing.T) {
	// Given
	command := commandName("parse-auth")

	// When
	got := defaultsFor(command)

	// Then
	assertOptionalString(t, got.logLevel, "error")
	if got.probe != (probePatch{}) || got.auth != (authPatch{}) || got.serve != (servePatch{}) {
		t.Fatalf("defaultsFor(parse-auth) command patches = %#v, want empty", got)
	}
}

func TestResolveRawInvocation_mergesEachFieldBySourcePrecedence(t *testing.T) {
	// Given
	file := fileConfig{
		LogLevel: testOptionalString("warn"),
		Serve: servePatch{
			Portal:            testOptionalString("file-portal"),
			Gateway:           testOptionalString("file-gateway"),
			DNSMode:           testOptionalString("vpn"),
			DNSServers:        testOptionalString("file-dns"),
			SOCKSUsername:     testOptionalString("file-user"),
			SOCKSPassword:     testOptionalString("file-password"),
			HandshakeTimeout:  testOptionalString("11s"),
			ConnectTimeout:    testOptionalString("31s"),
			MaxConnections:    testOptionalString("111"),
			HostID:            testOptionalString("file-host"),
			Browser:           testOptionalString("edge"),
			BrowserPath:       testOptionalString("file-browser"),
			BrowserProfileDir: testOptionalString("file-profile"),
			Timeout:           testOptionalString("2m"),
			DebugLog:          testOptionalString("file-debug.jsonl"),
		},
	}
	lookupEnv := testLookupEnv(map[string]string{
		"GP_SOCKS_LOG_LEVEL":       "info",
		"GP_SOCKS_PORTAL":          "env-portal",
		"GP_SOCKS_GATEWAY":         "env-gateway",
		"GP_SOCKS_DNS_SERVERS":     "env-dns",
		"GP_SOCKS_USERNAME":        "env-user",
		"GP_SOCKS_PASSWORD":        "env-password",
		"GP_SOCKS_CONNECT_TIMEOUT": "32s",
		"GP_SOCKS_HOST_ID":         "env-host",
		"GP_SOCKS_BROWSER_PATH":    "env-browser",
		"GP_SOCKS_TIMEOUT":         "45s",
	})
	cli := cliInvocation{
		command:  commandName("serve"),
		logLevel: testOptionalString("debug"),
		serve: servePatch{
			Gateway:        testOptionalString("cli-gateway"),
			DNSMode:        testOptionalString("system"),
			DNSServers:     testOptionalString(""),
			SOCKSPassword:  testOptionalString("cli-password"),
			MaxConnections: testOptionalString("333"),
			BrowserPath:    testOptionalString("cli-browser"),
		},
	}

	// When
	got, err := resolveRawInvocation(cli, file, lookupEnv)

	// Then
	if err != nil {
		t.Fatalf("resolveRawInvocation() error = %v", err)
	}
	assertOptionalString(t, got.logLevel, "debug")
	assertOptionalString(t, got.serve.Listen, "127.0.0.1:1080")
	assertOptionalString(t, got.serve.Portal, "env-portal")
	assertOptionalString(t, got.serve.Gateway, "cli-gateway")
	assertOptionalString(t, got.serve.DNSMode, "system")
	assertOptionalString(t, got.serve.DNSServers, "")
	assertOptionalString(t, got.serve.SOCKSUsername, "env-user")
	if got.serve.SOCKSPassword.value != "cli-password" || !got.serve.SOCKSPassword.present {
		t.Fatal("resolved SOCKS password did not use CLI precedence")
	}
	assertOptionalString(t, got.serve.HandshakeTimeout, "11s")
	assertOptionalString(t, got.serve.ConnectTimeout, "32s")
	assertOptionalString(t, got.serve.MaxConnections, "333")
	assertOptionalString(t, got.serve.HostID, "env-host")
	assertOptionalString(t, got.serve.Browser, "edge")
	assertOptionalString(t, got.serve.BrowserPath, "cli-browser")
	assertOptionalString(t, got.serve.BrowserProfileDir, "file-profile")
	assertOptionalString(t, got.serve.Timeout, "45s")
	assertOptionalString(t, got.serve.DebugLog, "file-debug.jsonl")
}

func TestResolveRawInvocation_preservesPresentEmptyEnvironmentValues(t *testing.T) {
	// Given
	file := fileConfig{
		Auth: authPatch{
			Portal:      testOptionalString("file-portal"),
			BrowserPath: testOptionalString("file-browser"),
			DebugLog:    testOptionalString("file-debug.jsonl"),
		},
	}
	lookupEnv := testLookupEnv(map[string]string{
		"GP_SOCKS_PORTAL":       "",
		"GP_SOCKS_BROWSER_PATH": "",
		"GP_SOCKS_DEBUG_LOG":    "",
	})
	cli := cliInvocation{command: commandName("auth")}

	// When
	got, err := resolveRawInvocation(cli, file, lookupEnv)

	// Then
	if err != nil {
		t.Fatalf("resolveRawInvocation() error = %v", err)
	}
	assertOptionalString(t, got.auth.Portal, "")
	assertOptionalString(t, got.auth.BrowserPath, "")
	assertOptionalString(t, got.auth.DebugLog, "")
}

func TestResolveRawInvocation_CLIOverridesEnvironmentForBrowserPath_whenBothPresent(t *testing.T) {
	// Given
	file := fileConfig{Auth: authPatch{BrowserPath: testOptionalString("file-browser")}}
	lookupEnv := testLookupEnv(map[string]string{"GP_SOCKS_BROWSER_PATH": "env-browser"})
	cli := cliInvocation{
		command: commandName("auth"),
		auth:    authPatch{BrowserPath: testOptionalString("cli-browser")},
	}

	// When
	got, err := resolveRawInvocation(cli, file, lookupEnv)

	// Then
	if err != nil {
		t.Fatalf("resolveRawInvocation() error = %v", err)
	}
	assertOptionalString(t, got.auth.BrowserPath, "cli-browser")
}
