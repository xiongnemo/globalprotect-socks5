package app

import "testing"

func TestResolveRawInvocation_readsApplicableProbeEnvironment(t *testing.T) {
	// Given
	lookupEnv := testLookupEnv(map[string]string{
		"GP_SOCKS_LOG_LEVEL": "debug",
		"GP_SOCKS_PORTAL":    "env-portal",
		"GP_SOCKS_HOST_ID":   "env-host",
		"GP_SOCKS_SSO_FILE":  "env-sso.html",
		"GP_SOCKS_DEBUG_LOG": "env-debug.jsonl",
	})
	cli := cliInvocation{command: commandName("probe")}

	// When
	got, err := resolveRawInvocation(cli, fileConfig{}, lookupEnv)

	// Then
	if err != nil {
		t.Fatalf("resolveRawInvocation() error = %v", err)
	}
	assertOptionalString(t, got.logLevel, "debug")
	assertOptionalString(t, got.probe.Portal, "env-portal")
	assertOptionalString(t, got.probe.HostID, "env-host")
	assertOptionalString(t, got.probe.SSOFile, "env-sso.html")
	assertOptionalString(t, got.probe.DebugLog, "env-debug.jsonl")
}

func TestResolveRawInvocation_readsApplicableAuthEnvironment(t *testing.T) {
	// Given
	lookupEnv := testLookupEnv(map[string]string{
		"GP_SOCKS_LOG_LEVEL":           "info",
		"GP_SOCKS_PORTAL":              "env-portal",
		"GP_SOCKS_HOST_ID":             "env-host",
		"GP_SOCKS_BROWSER":             "chrome",
		"GP_SOCKS_BROWSER_PATH":        "env-browser",
		"GP_SOCKS_BROWSER_PROFILE_DIR": "env-profile",
		"GP_SOCKS_TIMEOUT":             "30s",
		"GP_SOCKS_DEBUG_LOG":           "env-debug.jsonl",
	})
	cli := cliInvocation{command: commandName("auth")}

	// When
	got, err := resolveRawInvocation(cli, fileConfig{}, lookupEnv)

	// Then
	if err != nil {
		t.Fatalf("resolveRawInvocation() error = %v", err)
	}
	assertOptionalString(t, got.logLevel, "info")
	assertOptionalString(t, got.auth.Portal, "env-portal")
	assertOptionalString(t, got.auth.HostID, "env-host")
	assertOptionalString(t, got.auth.Browser, "chrome")
	assertOptionalString(t, got.auth.BrowserPath, "env-browser")
	assertOptionalString(t, got.auth.BrowserProfileDir, "env-profile")
	assertOptionalString(t, got.auth.Timeout, "30s")
	assertOptionalString(t, got.auth.DebugLog, "env-debug.jsonl")
}

func TestResolveRawInvocation_readsApplicableServeEnvironment(t *testing.T) {
	// Given
	lookupEnv := testLookupEnv(map[string]string{
		"GP_SOCKS_LOG_LEVEL":           "warn",
		"GP_SOCKS_LISTEN":              "127.0.0.1:2080",
		"GP_SOCKS_PORTAL":              "env-portal",
		"GP_SOCKS_GATEWAY":             "env-gateway",
		"GP_SOCKS_HOST_ID":             "env-host",
		"GP_SOCKS_BROWSER":             "edge",
		"GP_SOCKS_BROWSER_PATH":        "env-browser",
		"GP_SOCKS_BROWSER_PROFILE_DIR": "env-profile",
		"GP_SOCKS_TIMEOUT":             "90s",
		"GP_SOCKS_DEBUG_LOG":           "env-debug.jsonl",
	})
	cli := cliInvocation{command: commandName("serve")}

	// When
	got, err := resolveRawInvocation(cli, fileConfig{}, lookupEnv)

	// Then
	if err != nil {
		t.Fatalf("resolveRawInvocation() error = %v", err)
	}
	assertOptionalString(t, got.logLevel, "warn")
	assertOptionalString(t, got.serve.Listen, "127.0.0.1:2080")
	assertOptionalString(t, got.serve.Portal, "env-portal")
	assertOptionalString(t, got.serve.Gateway, "env-gateway")
	assertOptionalString(t, got.serve.HostID, "env-host")
	assertOptionalString(t, got.serve.Browser, "edge")
	assertOptionalString(t, got.serve.BrowserPath, "env-browser")
	assertOptionalString(t, got.serve.BrowserProfileDir, "env-profile")
	assertOptionalString(t, got.serve.Timeout, "90s")
	assertOptionalString(t, got.serve.DebugLog, "env-debug.jsonl")
}

func TestResolveRawInvocation_doesNotReadConfigPathFromEnvironment(t *testing.T) {
	// Given
	lookupEnv := lookupEnvFunc(func(name string) (string, bool) {
		if name == "GP_SOCKS_CONFIG" {
			t.Fatal("resolveRawInvocation() consulted GP_SOCKS_CONFIG")
		}
		return "", false
	})
	cli := cliInvocation{command: commandName("probe")}

	// When
	_, err := resolveRawInvocation(cli, fileConfig{}, lookupEnv)

	// Then
	if err != nil {
		t.Fatalf("resolveRawInvocation() error = %v", err)
	}
}
