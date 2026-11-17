package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/userdirs"
)

// isolateHome points every variable that could reach the real home at
// temporary directories.
func isolateHome(t *testing.T) {
	t.Helper()
	for _, name := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(name, t.TempDir())
	}
}

// testDirs returns a resolver over a fresh temporary home and working
// directory; env supplies the variables it sees.
func testDirs(t *testing.T, env map[string]string) (dirs userdirs.Env, home, wd string) {
	t.Helper()
	isolateHome(t)
	home, wd = t.TempDir(), t.TempDir()
	return userdirs.Env{
		LookupEnv: testLookupEnv(env),
		HomeDir:   func() (string, error) { return home, nil },
		WorkDir:   func() (string, error) { return wd, nil },
	}, home, wd
}

func writeTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("log_level: \"error\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSelectConfig_resolvesAutomaticConfig(t *testing.T) {
	for _, setting := range []string{"XDG unset", "XDG absolute", "XDG relative"} {
		for _, test := range []struct {
			name             string
			atNew, atLegacy  bool
			wantLegacy, warn bool
		}{
			{"neither", false, false, false, false},
			{"new only", true, false, false, false},
			{"legacy only", false, true, true, true},
			{"both", true, true, false, false},
		} {
			t.Run(setting+"/"+test.name, func(t *testing.T) {
				env, base := map[string]string{}, ""
				switch setting {
				case "XDG absolute":
					base = t.TempDir()
					env["XDG_CONFIG_HOME"] = base
				case "XDG relative":
					env["XDG_CONFIG_HOME"] = "relative"
				}
				dirs, home, wd := testDirs(t, env)
				if base == "" {
					base = filepath.Join(home, ".config")
				}
				newPath, legacy := filepath.Join(base, "gp-socks", "config.yaml"), filepath.Join(wd, "config.yaml")
				if test.atNew {
					writeTestFile(t, newPath)
				}
				if test.atLegacy {
					writeTestFile(t, legacy)
				}

				got, err := selectConfig(optionalString{}, false, true, dirs)
				if err != nil {
					t.Fatalf("selectConfig() error = %v", err)
				}
				want := newPath
				if test.wantLegacy {
					want = legacy
				}
				if got.path != want || !got.allowMissing {
					t.Fatalf("selectConfig() = %#v, want optional %q", got, want)
				}
				if (got.legacyNotice != "") != test.warn {
					t.Fatalf("legacy notice = %q, want notice %t", got.legacyNotice, test.warn)
				}
				if test.warn && !strings.Contains(got.legacyNotice, `run "gp-socks migrate" to move it to `+newPath) {
					t.Fatalf("legacy notice = %q", got.legacyNotice)
				}
				if !test.atNew {
					if _, err := os.Stat(filepath.Dir(newPath)); !os.IsNotExist(err) {
						t.Fatal("resolving created the new directory; it must wait for the first write")
					}
				}
			})
		}
	}
}

func TestSelectConfig_emptyNewDirectoryDoesNotHideLegacyConfig(t *testing.T) {
	dirs, home, wd := testDirs(t, nil)
	if err := os.MkdirAll(filepath.Join(home, ".config", "gp-socks", "config.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(wd, "config.yaml"))
	got, err := selectConfig(optionalString{}, false, true, dirs)
	if err != nil {
		t.Fatal(err)
	}
	if got.path != filepath.Join(wd, "config.yaml") || got.legacyNotice == "" {
		t.Fatalf("selectConfig() = %#v, want the legacy file", got)
	}
}

func TestSelectConfig_withoutHomeFindsOnlyWorkingDirectoryConfig(t *testing.T) {
	dirs, _, wd := testDirs(t, nil)
	dirs.HomeDir = nil
	got, err := selectConfig(optionalString{}, false, true, dirs)
	if err != nil {
		t.Fatal(err)
	}
	if got.path != filepath.Join(wd, "config.yaml") || !got.allowMissing || got.legacyNotice != "" {
		t.Fatalf("selectConfig() = %#v, want optional ./config.yaml without a notice", got)
	}
}

func TestSelectConfig_returnsExplicitPath_withoutAutoFallback(t *testing.T) {
	dirs, home, _ := testDirs(t, nil)
	writeTestFile(t, filepath.Join(home, ".config", "gp-socks", "config.yaml"))
	cliPath := testOptionalString("relative/custom.yaml")
	got, err := selectConfig(cliPath, false, true, dirs)
	if err != nil {
		t.Fatalf("selectConfig() error = %v", err)
	}
	if got.path != cliPath.value || got.allowMissing || got.legacyNotice != "" {
		t.Fatalf("selectConfig() = %#v, want required explicit path", got)
	}
}

func TestSelectConfig_returnsDisabled_whenNoConfigSelected(t *testing.T) {
	dirs, _, _ := testDirs(t, nil)
	got, err := selectConfig(optionalString{}, true, true, dirs)
	if err != nil {
		t.Fatalf("selectConfig() error = %v", err)
	}
	if got.path != "" {
		t.Fatalf("selectConfig() = %#v, want disabled file layer", got)
	}
}

func TestSelectConfig_returnsDisabled_whenAutoConfigNotEnabled(t *testing.T) {
	dirs, _, _ := testDirs(t, nil)
	got, err := selectConfig(optionalString{}, false, false, dirs)
	if err != nil {
		t.Fatalf("selectConfig() error = %v", err)
	}
	if got.path != "" {
		t.Fatalf("selectConfig() = %#v, want no ambient file discovery", got)
	}
}

func TestSelectConfig_rejectsBlankExplicitPath(t *testing.T) {
	dirs, _, _ := testDirs(t, nil)
	if _, err := selectConfig(testOptionalString(" \t "), false, true, dirs); err == nil {
		t.Fatal("selectConfig() error = nil, want blank explicit path error")
	}
}

func TestSelectConfig_rejectsExplicitPathWithNoConfig(t *testing.T) {
	dirs, _, _ := testDirs(t, nil)
	if _, err := selectConfig(testOptionalString("custom.yaml"), true, true, dirs); err == nil {
		t.Fatal("selectConfig() error = nil, want mutually exclusive root flags")
	}
}
