package userdirs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrateRewritesReferences(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	legacy := filepath.Join(wd, "config.yaml")
	writeFile(t, legacy, "ca: gateway.pem\n")
	var gotDir string
	rewrite := func(data []byte, dir string) ([]byte, []PathRewrite, error) {
		gotDir = dir
		abs := filepath.Join(dir, "gateway.pem")
		return bytes.Replace(data, []byte("gateway.pem"), []byte(abs), 1), []PathRewrite{{Key: "ca", Old: "gateway.pem", New: abs}}, nil
	}
	plan, err := migrate(t, env, MigrateOptions{DryRun: true, Rewrite: rewrite})
	if err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(home, ".config", "gp-socks", "config.yaml")
	if !strings.Contains(plan, "rewrite ca in "+newPath+": gateway.pem -> "+filepath.Join(wd, "gateway.pem")) {
		t.Fatalf("plan lacks the rewrite:\n%s", plan)
	}
	if readFile(t, legacy) != "ca: gateway.pem\n" {
		t.Fatal("dry run rewrote the file")
	}
	if _, err := migrate(t, env, MigrateOptions{Rewrite: rewrite}); err != nil {
		t.Fatal(err)
	}
	if gotDir != wd {
		t.Fatalf("rewrite got directory %s, want %s", gotDir, wd)
	}
	if got := readFile(t, newPath); got != "ca: "+filepath.Join(wd, "gateway.pem")+"\n" {
		t.Fatalf("reference not rewritten: %q", got)
	}
	mustNotExist(t, legacy)

	// The rewritten file counts as identical to its legacy original.
	writeFile(t, legacy, "ca: gateway.pem\n")
	if _, err := migrate(t, env, MigrateOptions{Rewrite: rewrite}); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, legacy)
}

func TestMigrateFailedRewriteStillMoves(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	writeFile(t, filepath.Join(wd, "config.yaml"), legacyConfig)
	out, err := migrate(t, env, MigrateOptions{Rewrite: func([]byte, string) ([]byte, []PathRewrite, error) {
		return nil, nil, errors.New("unit test refusal")
	}})
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(home, ".config", "gp-socks", "config.yaml")) != legacyConfig || !strings.Contains(out, "skip rewriting") {
		t.Fatalf("failed rewrite was not reported or blocked the move:\n%s", out)
	}
}

func TestMigrateFrom(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	other := filepath.Join(wd, "vpn", "office.yaml")
	writeFile(t, other, legacyConfig)
	writeFile(t, filepath.Join(wd, "config.yaml"), "not this one")
	out, err := migrate(t, env, MigrateOptions{From: filepath.Join("vpn", "office.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(home, ".config", "gp-socks", "config.yaml")) != legacyConfig {
		t.Fatal("--from file was not moved")
	}
	mustNotExist(t, other)
	if readFile(t, filepath.Join(wd, "config.yaml")) != "not this one" || strings.Contains(out, "current directory") {
		t.Fatalf("--from still looked in the current directory:\n%s", out)
	}
	out, err = migrate(t, env, MigrateOptions{From: other})
	if err != nil || !strings.Contains(out, "nothing to migrate") {
		t.Fatalf("missing --from file: %v\n%s", err, out)
	}
}

func TestMigrateFromNewLocationIsNoop(t *testing.T) {
	env, home, _ := testEnv(t, nil)
	newPath := filepath.Join(home, ".config", "gp-socks", "config.yaml")
	writeFile(t, newPath, legacyConfig)
	env.WorkDir = func() (string, error) { return filepath.Dir(newPath), nil }
	out, err := migrate(t, env, MigrateOptions{})
	if err != nil || !strings.Contains(out, "nothing to migrate") {
		t.Fatalf("migrating the new location onto itself: %v\n%s", err, out)
	}
	if readFile(t, newPath) != legacyConfig {
		t.Fatal("configuration changed")
	}
}

func TestMigrateCopiesAcrossVolumes(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	legacy := filepath.Join(wd, "config.yaml")
	writeFile(t, legacy, legacyConfig)
	mtime := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	if err := os.Chtimes(legacy, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	rename = func(string, string) error { return errors.New("invalid cross-device link (unit test)") }
	t.Cleanup(func() { rename = os.Rename })
	if _, err := migrate(t, env, MigrateOptions{}); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(home, ".config", "gp-socks", "config.yaml")
	if readFile(t, newPath) != legacyConfig {
		t.Fatal("copied configuration differs")
	}
	mustNotExist(t, legacy)
	if info, _ := os.Stat(newPath); !info.ModTime().Equal(mtime) {
		t.Errorf("copy has mtime %v, want %v", info.ModTime(), mtime)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(newPath), ".gp-socks-migrate-*"))
	if len(leftovers) != 0 {
		t.Fatalf("copy left temporary files: %v", leftovers)
	}
}

func TestMigrateWithoutHomeFails(t *testing.T) {
	env, _, wd := testEnv(t, nil)
	env.HomeDir = nil
	legacy := filepath.Join(wd, "config.yaml")
	writeFile(t, legacy, legacyConfig)
	if _, err := migrate(t, env, MigrateOptions{}); !errors.Is(err, ErrNoHome) {
		t.Fatalf("Migrate() error = %v, want ErrNoHome", err)
	}
	if readFile(t, legacy) != legacyConfig {
		t.Fatal("a failed migration changed the legacy configuration")
	}
}
