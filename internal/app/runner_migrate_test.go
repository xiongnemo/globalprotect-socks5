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

// xdgRunner chdirs into a fresh working directory and returns a runner whose
// home is a fresh temporary directory, with every real-home variable isolated.
func xdgRunner(t *testing.T) (runner app.Runner, stdout, stderr *bytes.Buffer, home, wd string) {
	t.Helper()
	for _, name := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(name, t.TempDir())
	}
	wd = enterWorkingDirectory(t)
	home = t.TempDir()
	stdout, stderr = &bytes.Buffer{}, &bytes.Buffer{}
	runner = app.NewRunner(app.IO{
		Stdout:     stdout,
		Stderr:     stderr,
		LogWriter:  &bytes.Buffer{},
		HomeDir:    func() (string, error) { return home, nil },
		AutoConfig: true,
	})
	return runner, stdout, stderr, home, wd
}

func writeNestedConfig(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	writeRunnerConfig(t, path, contents)
}

func Test_Run_prefersXDGConfigOverWorkingDirectory(t *testing.T) {
	runner, _, stderr, home, wd := xdgRunner(t)
	writeNestedConfig(t, filepath.Join(home, ".config", "gp-socks", "config.yaml"), "log_level: \"error\"\n")
	writeRunnerConfig(t, filepath.Join(wd, "config.yaml"), "unknown: value\n")

	if err := runner.Run(context.Background(), []string{"parse-auth", testAuthArtifact}); err != nil {
		t.Fatalf("Run() error = %v, read ./config.yaml despite the XDG file", err)
	}
	if strings.Contains(stderr.String(), "old location") {
		t.Fatalf("stderr = %q, want no legacy notice", stderr.String())
	}
}

func Test_Run_announcesLegacyConfigOnStderrOnly(t *testing.T) {
	runner, stdout, stderr, home, wd := xdgRunner(t)
	writeRunnerConfig(t, filepath.Join(wd, "config.yaml"), "log_level: \"error\"\n")

	if err := runner.Run(context.Background(), []string{"parse-auth", testAuthArtifact}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := `gp-socks: using the configuration from the old location ` + filepath.Join(wd, "config.yaml") +
		`; run "gp-socks migrate" to move it to ` + filepath.Join(home, ".config", "gp-socks", "config.yaml") + "\n"
	if stderr.String() != want {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
	if strings.Contains(stdout.String(), "old location") {
		t.Fatalf("stdout = %q, legacy notice leaked into command output", stdout.String())
	}
}

func Test_Run_migrateMovesConfigAndRewritesRelativePaths(t *testing.T) {
	runner, stdout, _, home, wd := xdgRunner(t)
	legacy := filepath.Join(wd, "config.yaml")
	absoluteLog := filepath.Join(t.TempDir(), "gp-debug.jsonl")
	contents := "# operator notes\nserve:\n  browser_profile_dir: \".gp-browser-profile\" # keep IdP state\n  debug_log: \"" + filepath.ToSlash(absoluteLog) + "\"\n  socks_password: \"unit-test-only\"\n"
	if filepath.Separator == '\\' {
		contents = strings.Replace(contents, filepath.ToSlash(absoluteLog), strings.ReplaceAll(absoluteLog, `\`, `\\`), 1)
	}
	writeRunnerConfig(t, legacy, contents)
	newPath := filepath.Join(home, ".config", "gp-socks", "config.yaml")
	profile := filepath.Join(wd, ".gp-browser-profile")

	if err := runner.Run(context.Background(), []string{"migrate", "--dry-run"}); err != nil {
		t.Fatalf("dry run error = %v", err)
	}
	for _, want := range []string{"dry run", "current directory " + wd, "move " + legacy + " -> " + newPath, "rewrite serve.browser_profile_dir in " + newPath + ": .gp-browser-profile -> " + profile} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("plan lacks %q:\n%s", want, stdout.String())
		}
	}
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Fatal("dry run wrote the new configuration")
	}

	stdout.Reset()
	if err := runner.Run(context.Background(), []string{"migrate"}); err != nil {
		t.Fatalf("migrate error = %v\n%s", err, stdout.String())
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy configuration still exists")
	}
	moved, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# operator notes", "# keep IdP state", "unit-test-only"} {
		if !strings.Contains(string(moved), want) {
			t.Errorf("moved configuration lost %q:\n%s", want, moved)
		}
	}
	if strings.Contains(stdout.String(), "unit-test-only") {
		t.Fatal("migrate printed the configuration's contents")
	}
	// The rewritten file still passes the strict decoder, from anywhere.
	if err := runner.Run(context.Background(), []string{"--config", newPath, "parse-auth", testAuthArtifact}); err != nil {
		t.Fatalf("rewritten configuration does not load: %v\n%s", err, moved)
	}

	stdout.Reset()
	if err := runner.Run(context.Background(), []string{"migrate"}); err != nil || !strings.Contains(stdout.String(), "nothing to migrate") {
		t.Fatalf("second migrate: %v\n%s", err, stdout.String())
	}
}

func Test_Run_migrateConflictKeepsBothAndFails(t *testing.T) {
	runner, stdout, _, home, wd := xdgRunner(t)
	legacy, newPath := filepath.Join(wd, "config.yaml"), filepath.Join(home, ".config", "gp-socks", "config.yaml")
	writeRunnerConfig(t, legacy, "log_level: \"debug\"\n")
	writeNestedConfig(t, newPath, "log_level: \"error\"\n")

	if err := runner.Run(context.Background(), []string{"migrate"}); err == nil {
		t.Fatal("Run() error = nil, want a conflict")
	}
	if !strings.Contains(stdout.String(), "conflict") {
		t.Fatalf("stdout = %q, want the conflict reported", stdout.String())
	}
	for path, want := range map[string]string{legacy: "debug", newPath: "error"} {
		if got, _ := os.ReadFile(path); !strings.Contains(string(got), want) {
			t.Fatalf("%s changed: %q", path, got)
		}
	}
}

func Test_Run_migrateFrom(t *testing.T) {
	runner, _, _, home, wd := xdgRunner(t)
	writeNestedConfig(t, filepath.Join(wd, "vpn", "office.yaml"), "log_level: \"info\"\n")

	if err := runner.Run(context.Background(), []string{"migrate", "-from", filepath.Join("vpn", "office.yaml")}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(home, ".config", "gp-socks", "config.yaml")); err != nil || !strings.Contains(string(got), "info") {
		t.Fatalf("--from file not moved: %q, %v", got, err)
	}
}

func Test_Run_migrateRejectsConfigRootFlags(t *testing.T) {
	runner, _, stderr, _, _ := xdgRunner(t)
	for _, args := range [][]string{{"--config", "x.yaml", "migrate"}, {"--no-config", "migrate"}, {"migrate", "stray"}} {
		stderr.Reset()
		if err := runner.Run(context.Background(), args); err == nil {
			t.Errorf("Run(%q) error = nil", args)
		}
	}
}
