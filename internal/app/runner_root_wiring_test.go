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
)

const testAuthArtifact = "globalprotectcallback:cas-as=1&un=alice&token=secret-token"

func Test_Run_acceptsRootFlagsBeforeCommand(t *testing.T) {
	// Given
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	var stdout bytes.Buffer
	runner := app.NewRunner(app.IO{Stdout: &stdout})

	// When
	err := runner.Run(context.Background(), []string{
		"--config", configPath,
		"--log-level", "error",
		"parse-auth", testAuthArtifact,
	})

	// Then
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "kind=cas username=alice") {
		t.Fatalf("stdout = %q, want parsed artifact summary", stdout.String())
	}
}

func Test_Run_keepsCommandFirstFormsAccepted(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "parse-auth", args: []string{"parse-auth", testAuthArtifact}},
		{name: "probe", args: []string{"probe"}},
		{name: "auth", args: []string{"auth"}},
		{name: "serve", args: []string{"serve", "--listen", "bad-listen-address"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			var stderr bytes.Buffer
			runner := app.NewRunner(app.IO{Stderr: &stderr})

			// When
			err := runner.Run(context.Background(), test.args)

			// Then
			if errors.Is(err, app.ErrUsage) {
				t.Fatalf("Run() error = %v, command-first form was not dispatched; stderr=%q", err, stderr.String())
			}
		})
	}
}

func Test_Run_rejectsConfigAsAuthCommandFlag(t *testing.T) {
	// Given
	var stderr bytes.Buffer
	runner := app.NewRunner(app.IO{Stderr: &stderr})

	// When
	err := runner.Run(context.Background(), []string{"auth", "--config", "config.yaml"})

	// Then
	if err == nil || !strings.Contains(err.Error(), "parse auth flags") {
		t.Fatalf("Run() error = %v, want auth command flag error", err)
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined: -config") {
		t.Fatalf("stderr = %q, want undefined auth flag diagnostic", stderr.String())
	}
}

func Test_Run_rejectsNoConfigAsAuthCommandFlag(t *testing.T) {
	var stderr bytes.Buffer
	runner := app.NewRunner(app.IO{Stderr: &stderr})

	err := runner.Run(context.Background(), []string{"auth", "--no-config"})

	if err == nil || !strings.Contains(err.Error(), "parse auth flags") {
		t.Fatalf("Run() error = %v, want auth command flag error", err)
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined: -no-config") {
		t.Fatalf("stderr = %q, want undefined auth flag diagnostic", stderr.String())
	}
}

func Test_Run_treatsConfigAfterParseAuthAsArtifactOperand(t *testing.T) {
	// Given
	var stderr bytes.Buffer
	runner := app.NewRunner(app.IO{Stderr: &stderr})

	// When
	err := runner.Run(context.Background(), []string{"parse-auth", "--config"})

	// Then
	if err == nil || !strings.Contains(err.Error(), "parse auth artifact") {
		t.Fatalf("Run() error = %v, want artifact parse error", err)
	}
	if errors.Is(err, app.ErrUsage) {
		t.Fatalf("Run() error = %v, parse-auth operand was treated as a root flag", err)
	}
}

func Test_Run_treatsNoConfigAfterParseAuthAsArtifactOperand(t *testing.T) {
	var stderr bytes.Buffer
	runner := app.NewRunner(app.IO{Stderr: &stderr})

	err := runner.Run(context.Background(), []string{"parse-auth", "--no-config"})

	if err == nil || !strings.Contains(err.Error(), "parse auth artifact") {
		t.Fatalf("Run() error = %v, want artifact parse error", err)
	}
	if errors.Is(err, app.ErrUsage) {
		t.Fatalf("Run() error = %v, parse-auth operand was treated as a root flag", err)
	}
}
