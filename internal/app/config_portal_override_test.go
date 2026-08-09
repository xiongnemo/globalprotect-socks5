package app

import (
	"strings"
	"testing"
)

func TestResolveRawInvocationRejectsBlankServePortalOverride(t *testing.T) {
	tests := []struct {
		name      string
		lookupEnv lookupEnvFunc
		cliPortal optionalString
	}{
		{name: "environment whitespace", lookupEnv: testLookupEnv(map[string]string{"GP_SOCKS_PORTAL": " \t "})},
		{name: "CLI whitespace", lookupEnv: testLookupEnv(map[string]string{}), cliPortal: testOptionalString(" \t ")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const lowerPortal = "private-file-portal"
			file := fileConfig{Serve: servePatch{Portal: testOptionalString(lowerPortal)}}
			cli := cliInvocation{command: commandServe, serve: servePatch{Portal: test.cliPortal}}
			_, err := resolveRawInvocation(cli, file, test.lookupEnv)
			if err == nil {
				t.Fatal("resolveRawInvocation() error = nil, want portal-clearing configuration error")
			}
			if strings.Contains(err.Error(), lowerPortal) {
				t.Fatalf("resolveRawInvocation() error exposed lower-precedence portal: %v", err)
			}
		})
	}
}

func TestResolveRawInvocationKeepsBlankServePortalWithoutLowerPortal(t *testing.T) {
	tests := []struct {
		name      string
		lookupEnv lookupEnvFunc
		cliPortal optionalString
		want      string
	}{
		{name: "environment whitespace", lookupEnv: testLookupEnv(map[string]string{"GP_SOCKS_PORTAL": " \t "}), want: " \t "},
		{name: "CLI whitespace", lookupEnv: testLookupEnv(map[string]string{}), cliPortal: testOptionalString(" \t "), want: " \t "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cli := cliInvocation{command: commandServe, serve: servePatch{Portal: test.cliPortal}}
			got, err := resolveRawInvocation(cli, fileConfig{}, test.lookupEnv)
			if err != nil {
				t.Fatalf("resolveRawInvocation() error = %v, want direct mode", err)
			}
			assertOptionalString(t, got.serve.Portal, test.want)
		})
	}
}

func TestResolveRawInvocationAllowsNonblankCLIPortalAfterBlankEnvironment(t *testing.T) {
	file := fileConfig{Serve: servePatch{Portal: testOptionalString("file-portal")}}
	lookupEnv := testLookupEnv(map[string]string{"GP_SOCKS_PORTAL": " \t "})
	cli := cliInvocation{
		command: commandServe,
		serve:   servePatch{Portal: testOptionalString("cli-portal")},
	}
	got, err := resolveRawInvocation(cli, file, lookupEnv)
	if err != nil {
		t.Fatalf("resolveRawInvocation() error = %v", err)
	}
	assertOptionalString(t, got.serve.Portal, "cli-portal")
}
