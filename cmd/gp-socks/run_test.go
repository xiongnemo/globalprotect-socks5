package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
)

const runTestAuthArtifact = "globalprotectcallback:cas-as=1&un=alice&token=secret-token"

func TestRun_returnsExitCodeForRunnerOutcome(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "success returns zero", args: []string{"parse-auth", runTestAuthArtifact}, want: 0},
		{name: "failure returns one", args: []string{"parse-auth", "invalid-artifact"}, want: 1},
		{name: "usage returns two", args: nil, want: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			ioConfig := app.IO{
				Stdout:    io.Discard,
				Stderr:    io.Discard,
				LogWriter: io.Discard,
				LookupEnv: func(string) (string, bool) { return "", false },
			}

			// When
			got := run(context.Background(), test.args, ioConfig)

			// Then
			if got != test.want {
				t.Fatalf("run() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestRun_usesInjectedEnvironmentAndLogWriter(t *testing.T) {
	// Given
	t.Setenv("GP_SOCKS_LOG_LEVEL", "error")
	lookupCalls := 0
	var applicationLog bytes.Buffer
	ioConfig := app.IO{
		Stdout:    io.Discard,
		Stderr:    io.Discard,
		LogWriter: &applicationLog,
		LookupEnv: func(name string) (string, bool) {
			lookupCalls++
			if name == "GP_SOCKS_LOG_LEVEL" {
				return "debug", true
			}
			return "", false
		},
	}

	// When
	code := run(context.Background(), []string{"parse-auth", runTestAuthArtifact}, ioConfig)

	// Then
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if lookupCalls == 0 {
		t.Fatal("injected environment lookup was not called")
	}
	for _, record := range []string{`"msg":"command started"`, `"msg":"command completed"`} {
		if !strings.Contains(applicationLog.String(), record) {
			t.Errorf("application log = %q, want %s", applicationLog.String(), record)
		}
	}
}
