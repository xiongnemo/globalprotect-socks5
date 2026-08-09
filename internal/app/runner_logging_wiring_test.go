package app_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_Run_emitsCommandLifecycleRecordsAtDebugLevel(t *testing.T) {
	// Given
	var applicationLog bytes.Buffer
	runner := app.NewRunner(app.IO{LogWriter: &applicationLog})

	// When
	err := runner.Run(context.Background(), []string{
		"--log-level", "debug", "parse-auth", testAuthArtifact,
	})

	// Then
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := "" +
		`{"level":"DEBUG","msg":"command started","command":"parse-auth"}` + "\n" +
		`{"level":"INFO","msg":"command completed","command":"parse-auth"}` + "\n"
	if applicationLog.String() != want {
		t.Fatalf("application log = %q, want %q", applicationLog.String(), want)
	}
}

func Test_Run_suppressesLifecycleRecordsAtDefaultAndErrorLevels(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "default", args: []string{"parse-auth", testAuthArtifact}},
		{name: "explicit error", args: []string{"--log-level", "error", "parse-auth", testAuthArtifact}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			var applicationLog bytes.Buffer
			runner := app.NewRunner(app.IO{LogWriter: &applicationLog})

			// When
			err := runner.Run(context.Background(), test.args)

			// Then
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if applicationLog.Len() != 0 {
				t.Fatalf("application log = %q, want empty", applicationLog.String())
			}
		})
	}
}

func Test_Run_keepsProtocolDebugLogIndependentFromApplicationLevel(t *testing.T) {
	// Given
	protocolByLevel := make(map[string][]byte)
	for _, level := range []string{"error", "debug"} {
		server := newRejectedPreloginServer(t)
		debugPath := filepath.Join(t.TempDir(), "probe.jsonl")
		var applicationLog bytes.Buffer
		runner := app.NewRunner(app.IO{HTTPClient: server.Client(), LogWriter: &applicationLog})

		// When
		err := runner.Run(context.Background(), []string{
			"--log-level", level,
			"probe", "--portal", server.URL, "--debug-log", debugPath,
		})
		server.Close()

		// Then
		if !errors.Is(err, gp.ErrInvalidPrelogin) {
			t.Fatalf("Run(%s) error = %v, want ErrInvalidPrelogin", level, err)
		}
		contents, readErr := os.ReadFile(debugPath)
		if readErr != nil {
			t.Fatalf("ReadFile(%s) error = %v", level, readErr)
		}
		protocolByLevel[level] = contents
		assertApplicationLogExcludesProtocolData(t, applicationLog.String())
	}
	if !bytes.Equal(protocolByLevel["error"], protocolByLevel["debug"]) {
		t.Fatalf("protocol logs differ by application level:\nerror=%q\ndebug=%q", protocolByLevel["error"], protocolByLevel["debug"])
	}
}

func Test_Run_debugLevelWithoutDebugLogCreatesNoProtocolFile(t *testing.T) {
	// Given
	workingDirectory := t.TempDir()
	originalDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDirectory) })
	server := newRejectedPreloginServer(t)
	defer server.Close()
	var applicationLog bytes.Buffer
	runner := app.NewRunner(app.IO{
		HTTPClient: server.Client(),
		LogWriter:  &applicationLog,
		LookupEnv:  func(string) (string, bool) { return "", false },
	})

	// When
	runErr := runner.Run(context.Background(), []string{
		"--log-level", "debug", "probe", "--portal", server.URL,
	})

	// Then
	if !errors.Is(runErr, gp.ErrInvalidPrelogin) {
		t.Fatalf("Run() error = %v, want ErrInvalidPrelogin", runErr)
	}
	entries, readErr := os.ReadDir(workingDirectory)
	if readErr != nil {
		t.Fatalf("ReadDir() error = %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("working directory entries = %v, want no protocol file", entries)
	}
}

func assertApplicationLogExcludesProtocolData(t *testing.T, applicationLog string) {
	t.Helper()
	for _, forbidden := range []string{
		"request_form_fields", "response_snippet", "transport_succeeded",
		"/global-protect/prelogin.esp", "diagnostic", "secret-cookie", "secret-saml",
	} {
		if strings.Contains(applicationLog, forbidden) {
			t.Fatalf("application log contains protocol or secret value %q: %q", forbidden, applicationLog)
		}
	}
}
