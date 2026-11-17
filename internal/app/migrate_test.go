package app

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewriteConfigPaths(t *testing.T) {
	oldDir := t.TempDir()
	absolute := filepath.Join(t.TempDir(), "debug.jsonl")
	contents := `# notes
probe:
  sso_file: "sso.html"
  debug_log: ""
auth:
  browser_profile_dir: 'profiles/gp' # IdP state
  debug_log: ' padded.jsonl '
serve:
  portal: "relative-looking-but-not-a-path"
  browser_path: "bin/chrome"
  debug_log: '` + absolute + `'
`
	out, rewrites, err := rewriteConfigPaths([]byte(contents), oldDir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"probe.sso_file":           filepath.Join(oldDir, "sso.html"),
		"auth.browser_profile_dir": filepath.Join(oldDir, "profiles", "gp"),
		"serve.browser_path":       filepath.Join(oldDir, "bin", "chrome"),
	}
	if len(rewrites) != len(want) {
		t.Fatalf("rewrites = %+v, want %d", rewrites, len(want))
	}
	for _, r := range rewrites {
		if want[r.Key] != r.New {
			t.Errorf("rewrite %s -> %s, want %s", r.Key, r.New, want[r.Key])
		}
	}
	config, err := decodeConfig(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("rewritten config fails the strict decoder: %v\n%s", err, out)
	}
	if config.Auth.BrowserProfileDir.value != want["auth.browser_profile_dir"] ||
		config.Serve.DebugLog.value != absolute ||
		config.Auth.DebugLog.value != " padded.jsonl " ||
		config.Probe.DebugLog.value != "" ||
		config.Serve.Portal.value != "relative-looking-but-not-a-path" {
		t.Fatalf("rewrite changed the wrong values: %+v", config)
	}
	for _, comment := range []string{"# notes", "# IdP state"} {
		if !strings.Contains(string(out), comment) {
			t.Errorf("lost comment %q", comment)
		}
	}

	unchanged := "serve:\n  debug_log: '" + absolute + "'\n"
	if out, rewrites, err := rewriteConfigPaths([]byte(unchanged), oldDir); err != nil || len(rewrites) != 0 || string(out) != unchanged {
		t.Fatalf("nothing to rewrite, yet got %q %+v %v", out, rewrites, err)
	}
	if _, _, err := rewriteConfigPaths([]byte("serve: [\n"), oldDir); err == nil {
		t.Fatal("invalid YAML was accepted")
	}
}
