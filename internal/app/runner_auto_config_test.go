package app_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
)

func Test_Run_autoLoadsConfigYAMLFromWorkingDirectory(t *testing.T) {
	workingDirectory := enterWorkingDirectory(t)
	writeRunnerConfig(t, filepath.Join(workingDirectory, "config.yaml"), "log_level: \"debug\"\n")
	var applicationLog bytes.Buffer
	runner := app.NewRunner(app.IO{AutoConfig: true, LogWriter: &applicationLog})

	err := runner.Run(context.Background(), []string{"parse-auth", testAuthArtifact})

	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(applicationLog.String(), `"msg":"command started"`) {
		t.Fatalf("application log = %q, want auto-loaded debug level", applicationLog.String())
	}
}

func Test_Run_ignoresMissingAutomaticConfigYAML(t *testing.T) {
	enterWorkingDirectory(t)
	runner := app.NewRunner(app.IO{AutoConfig: true})

	err := runner.Run(context.Background(), []string{"parse-auth", testAuthArtifact})

	if err != nil {
		t.Fatalf("Run() error = %v, want missing automatic config ignored", err)
	}
}

func Test_Run_discoversOnlyExactConfigYAMLName(t *testing.T) {
	workingDirectory := enterWorkingDirectory(t)
	writeRunnerConfig(t, filepath.Join(workingDirectory, "config.yml"), "unknown: value\n")
	writeRunnerConfig(t, filepath.Join(workingDirectory, "config.json"), "unknown: value\n")
	runner := app.NewRunner(app.IO{AutoConfig: true})

	err := runner.Run(context.Background(), []string{"parse-auth", testAuthArtifact})

	if err != nil {
		t.Fatalf("Run() error = %v, discovered a non-config.yaml file", err)
	}
}

func Test_Run_rejectsInvalidAutomaticConfigYAML(t *testing.T) {
	workingDirectory := enterWorkingDirectory(t)
	writeRunnerConfig(t, filepath.Join(workingDirectory, "config.yaml"), "unknown: value\n")
	runner := app.NewRunner(app.IO{AutoConfig: true})

	err := runner.Run(context.Background(), []string{"parse-auth", testAuthArtifact})

	if err == nil {
		t.Fatal("Run() error = nil, want invalid automatic config error")
	}
}

func Test_Run_explicitConfigSuppressesAutomaticDiscovery(t *testing.T) {
	workingDirectory := enterWorkingDirectory(t)
	writeRunnerConfig(t, filepath.Join(workingDirectory, "config.yaml"), "unknown: value\n")
	explicitPath := filepath.Join(workingDirectory, "explicit.yaml")
	writeRunnerConfig(t, explicitPath, "log_level: \"error\"\n")
	runner := app.NewRunner(app.IO{AutoConfig: true})

	err := runner.Run(context.Background(), []string{
		"--config", explicitPath, "parse-auth", testAuthArtifact,
	})

	if err != nil {
		t.Fatalf("Run() error = %v, explicit config did not suppress automatic discovery", err)
	}
}

func Test_Run_noConfigDisablesAutomaticDiscovery(t *testing.T) {
	workingDirectory := enterWorkingDirectory(t)
	writeRunnerConfig(t, filepath.Join(workingDirectory, "config.yaml"), "unknown: value\n")
	runner := app.NewRunner(app.IO{AutoConfig: true})

	err := runner.Run(context.Background(), []string{
		"--no-config", "parse-auth", testAuthArtifact,
	})

	if err != nil {
		t.Fatalf("Run() error = %v, --no-config did not disable automatic discovery", err)
	}
}

func Test_Run_noConfigStillAppliesEnvironmentAndCLI(t *testing.T) {
	workingDirectory := enterWorkingDirectory(t)
	writeRunnerConfig(t, filepath.Join(workingDirectory, "config.yaml"), "unknown: value\n")
	var applicationLog bytes.Buffer
	runner := app.NewRunner(app.IO{
		AutoConfig: true,
		LogWriter:  &applicationLog,
		LookupEnv: func(name string) (string, bool) {
			if name == "GP_SOCKS_LOG_LEVEL" {
				return "info", true
			}
			return "", false
		},
	})

	err := runner.Run(context.Background(), []string{
		"--no-config", "--log-level", "debug", "parse-auth", testAuthArtifact,
	})

	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(applicationLog.String(), `"level":"DEBUG"`) {
		t.Fatalf("application log = %q, want CLI over environment after --no-config", applicationLog.String())
	}
}

func Test_Run_noConfigFalseKeepsAutomaticDiscoveryEnabled(t *testing.T) {
	workingDirectory := enterWorkingDirectory(t)
	writeRunnerConfig(t, filepath.Join(workingDirectory, "config.yaml"), "unknown: value\n")
	runner := app.NewRunner(app.IO{AutoConfig: true})

	err := runner.Run(context.Background(), []string{
		"--no-config=false", "parse-auth", testAuthArtifact,
	})

	if err == nil {
		t.Fatal("Run() error = nil, --no-config=false unexpectedly disabled discovery")
	}
}

func Test_Run_rejectsConfigTogetherWithNoConfig(t *testing.T) {
	workingDirectory := enterWorkingDirectory(t)
	explicitPath := filepath.Join(workingDirectory, "missing-explicit.yaml")
	runner := app.NewRunner(app.IO{AutoConfig: true})

	err := runner.Run(context.Background(), []string{
		"--config", explicitPath, "--no-config", "parse-auth", testAuthArtifact,
	})

	if err == nil {
		t.Fatal("Run() error = nil, want mutually exclusive root flag error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("Run() error = %v, want flag conflict before file I/O", err)
	}
}

func Test_Run_automaticConfigFailureLogDoesNotExposeContents(t *testing.T) {
	workingDirectory := enterWorkingDirectory(t)
	writeRunnerConfig(t, filepath.Join(workingDirectory, "config.yaml"), "SECRET_CONFIG_KEY: SECRET_CONFIG_VALUE\n")
	var applicationLog bytes.Buffer
	runner := app.NewRunner(app.IO{AutoConfig: true, LogWriter: &applicationLog})

	err := runner.Run(context.Background(), []string{"parse-auth", testAuthArtifact})

	if err == nil {
		t.Fatal("Run() error = nil, want invalid automatic config error")
	}
	if !strings.Contains(applicationLog.String(), `"stage":"config"`) {
		t.Fatalf("application log = %q, want configuration classification", applicationLog.String())
	}
	for _, forbidden := range []string{"SECRET_CONFIG_KEY", "SECRET_CONFIG_VALUE", "config.yaml"} {
		if strings.Contains(applicationLog.String(), forbidden) {
			t.Errorf("application log leaked %q: %q", forbidden, applicationLog.String())
		}
	}
}

func Test_NewRunner_doesNotAutoDiscoverConfigUnlessEnabled(t *testing.T) {
	workingDirectory := enterWorkingDirectory(t)
	writeRunnerConfig(t, filepath.Join(workingDirectory, "config.yaml"), "unknown: value\n")
	runner := app.NewRunner(app.IO{})

	err := runner.Run(context.Background(), []string{"parse-auth", testAuthArtifact})

	if err != nil {
		t.Fatalf("Run() error = %v, embedded runner read ambient config.yaml", err)
	}
}

func enterWorkingDirectory(t *testing.T) string {
	t.Helper()
	originalDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	workingDirectory := t.TempDir()
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	return workingDirectory
}
