package app

import (
	"strings"
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
	assertOptionalString(t, got.serve.Portal, "")
	assertOptionalString(t, got.serve.Gateway, "")
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
			HostID:            testOptionalString("file-host"),
			Browser:           testOptionalString("edge"),
			BrowserPath:       testOptionalString("file-browser"),
			BrowserProfileDir: testOptionalString("file-profile"),
			Timeout:           testOptionalString("2m"),
			DebugLog:          testOptionalString("file-debug.jsonl"),
		},
	}
	lookupEnv := testLookupEnv(map[string]string{
		"GP_SOCKS_LOG_LEVEL":    "info",
		"GP_SOCKS_PORTAL":       "env-portal",
		"GP_SOCKS_GATEWAY":      "env-gateway",
		"GP_SOCKS_HOST_ID":      "env-host",
		"GP_SOCKS_BROWSER_PATH": "env-browser",
		"GP_SOCKS_TIMEOUT":      "45s",
	})
	cli := cliInvocation{
		command:  commandName("serve"),
		logLevel: testOptionalString("debug"),
		serve: servePatch{
			Gateway:     testOptionalString("cli-gateway"),
			BrowserPath: testOptionalString("cli-browser"),
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

func TestResolveRawInvocation_rejectsFinalBlankServePortalOverride_whenLowerPortalIsNonblank(t *testing.T) {
	tests := []struct {
		name      string
		lookupEnv lookupEnvFunc
		cliPortal optionalString
	}{
		{
			name:      "environment whitespace",
			lookupEnv: testLookupEnv(map[string]string{"GP_SOCKS_PORTAL": " \t "}),
		},
		{
			name:      "CLI whitespace",
			lookupEnv: testLookupEnv(map[string]string{}),
			cliPortal: testOptionalString(" \t "),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			const lowerPortal = "private-file-portal"
			file := fileConfig{Serve: servePatch{Portal: testOptionalString(lowerPortal)}}
			cli := cliInvocation{
				command: commandServe,
				serve:   servePatch{Portal: test.cliPortal},
			}

			// When
			_, err := resolveRawInvocation(cli, file, test.lookupEnv)

			// Then
			if err == nil {
				t.Fatal("resolveRawInvocation() error = nil, want portal-clearing configuration error")
			}
			if strings.Contains(err.Error(), lowerPortal) {
				t.Fatalf("resolveRawInvocation() error exposed lower-precedence portal: %v", err)
			}
		})
	}
}

func TestResolveRawInvocation_keepsFinalBlankServePortal_whenNoLowerPortalIsNonblank(t *testing.T) {
	tests := []struct {
		name      string
		lookupEnv lookupEnvFunc
		cliPortal optionalString
		want      string
	}{
		{
			name:      "environment whitespace",
			lookupEnv: testLookupEnv(map[string]string{"GP_SOCKS_PORTAL": " \t "}),
			want:      " \t ",
		},
		{
			name:      "CLI whitespace",
			lookupEnv: testLookupEnv(map[string]string{}),
			cliPortal: testOptionalString(" \t "),
			want:      " \t ",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			cli := cliInvocation{
				command: commandServe,
				serve:   servePatch{Portal: test.cliPortal},
			}

			// When
			got, err := resolveRawInvocation(cli, fileConfig{}, test.lookupEnv)

			// Then
			if err != nil {
				t.Fatalf("resolveRawInvocation() error = %v, want direct mode", err)
			}
			assertOptionalString(t, got.serve.Portal, test.want)
		})
	}
}

func TestResolveRawInvocation_allowsNonblankCLIServePortal_afterBlankEnvironmentPortal(t *testing.T) {
	// Given
	file := fileConfig{Serve: servePatch{Portal: testOptionalString("file-portal")}}
	lookupEnv := testLookupEnv(map[string]string{"GP_SOCKS_PORTAL": " \t "})
	cli := cliInvocation{
		command: commandServe,
		serve:   servePatch{Portal: testOptionalString("cli-portal")},
	}

	// When
	got, err := resolveRawInvocation(cli, file, lookupEnv)

	// Then
	if err != nil {
		t.Fatalf("resolveRawInvocation() error = %v", err)
	}
	assertOptionalString(t, got.serve.Portal, "cli-portal")
}
