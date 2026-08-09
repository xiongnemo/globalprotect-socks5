package app

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDecodeConfig_acceptsEmptyMapping(t *testing.T) {
	got, err := decodeConfig(strings.NewReader("{}\n"))
	if err != nil {
		t.Fatalf("decodeConfig() error = %v", err)
	}
	if want := (fileConfig{}); !reflect.DeepEqual(got, want) {
		t.Fatalf("decodeConfig() = %#v, want %#v", got, want)
	}
}

func TestDecodeConfig_decodesCompleteSchema(t *testing.T) {
	reader := strings.NewReader(`log_level: "debug"
probe:
  portal: "https://probe.example.test"
  host_id: "probe-host"
  sso_file: "probe.html"
  debug_log: "probe.jsonl"
auth:
  portal: "https://auth.example.test"
  host_id: "auth-host"
  browser: "chrome"
  browser_path: "auth-browser"
  browser_profile_dir: "auth-profile"
  timeout: "45s"
  debug_log: "auth.jsonl"
serve:
  listen: "127.0.0.1:2080"
  socks_username: "serve-user"
  socks_password: "serve-password"
  handshake_timeout: "12s"
  connect_timeout: "34s"
  max_connections: "345"
  portal: "https://serve.example.test"
  gateway: "https://gateway.example.test"
  dns_mode: "vpn"
  dns_servers: "10.0.0.53,10.0.0.54"
  host_id: "serve-host"
  browser: "edge"
  browser_path: "serve-browser"
  browser_profile_dir: "serve-profile"
  timeout: "90s"
  debug_log: "serve.jsonl"
`)
	want := fileConfig{
		LogLevel: testOptionalString("debug"),
		Probe: probePatch{
			Portal: testOptionalString("https://probe.example.test"), HostID: testOptionalString("probe-host"),
			SSOFile: testOptionalString("probe.html"), DebugLog: testOptionalString("probe.jsonl"),
		},
		Auth: authPatch{
			Portal: testOptionalString("https://auth.example.test"), HostID: testOptionalString("auth-host"),
			Browser: testOptionalString("chrome"), BrowserPath: testOptionalString("auth-browser"),
			BrowserProfileDir: testOptionalString("auth-profile"), Timeout: testOptionalString("45s"),
			DebugLog: testOptionalString("auth.jsonl"),
		},
		Serve: servePatch{
			Listen: testOptionalString("127.0.0.1:2080"), Portal: testOptionalString("https://serve.example.test"),
			Gateway: testOptionalString("https://gateway.example.test"), HostID: testOptionalString("serve-host"),
			DNSMode: testOptionalString("vpn"), DNSServers: testOptionalString("10.0.0.53,10.0.0.54"),
			SOCKSUsername: testOptionalString("serve-user"), SOCKSPassword: testOptionalString("serve-password"),
			HandshakeTimeout: testOptionalString("12s"), ConnectTimeout: testOptionalString("34s"),
			MaxConnections: testOptionalString("345"),
			Browser:        testOptionalString("edge"), BrowserPath: testOptionalString("serve-browser"),
			BrowserProfileDir: testOptionalString("serve-profile"), Timeout: testOptionalString("90s"),
			DebugLog: testOptionalString("serve.jsonl"),
		},
	}

	got, err := decodeConfig(reader)
	if err != nil {
		t.Fatalf("decodeConfig() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("decodeConfig() did not decode the complete schema")
	}
}

func TestDecodeConfig_preservesExplicitEmptyStrings(t *testing.T) {
	reader := strings.NewReader(`log_level: ""
probe:
  portal: ""
auth:
  browser_path: ""
serve:
  debug_log: ""
`)
	want := fileConfig{
		LogLevel: testOptionalString(""),
		Probe:    probePatch{Portal: testOptionalString("")},
		Auth:     authPatch{BrowserPath: testOptionalString("")},
		Serve:    servePatch{DebugLog: testOptionalString("")},
	}

	got, err := decodeConfig(reader)
	if err != nil {
		t.Fatalf("decodeConfig() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decodeConfig() = %#v, want explicit empty values %#v", got, want)
	}
}

func TestDecodeConfig_acceptsPlainYAMLStringsAndDocumentMarkers(t *testing.T) {
	reader := strings.NewReader(`---
# Plain scalars that resolve to strings remain valid.
auth:
  portal: https://vpn.example.test
  timeout: 5m
serve:
  listen: 127.0.0.1:1080
...
`)

	got, err := decodeConfig(reader)
	if err != nil {
		t.Fatalf("decodeConfig() error = %v", err)
	}
	assertOptionalString(t, got.Auth.Portal, "https://vpn.example.test")
	assertOptionalString(t, got.Auth.Timeout, "5m")
	assertOptionalString(t, got.Serve.Listen, "127.0.0.1:1080")
}

func TestDecodeConfig_acceptsQuotedMergeTokenAsStringValue(t *testing.T) {
	got, err := decodeConfig(strings.NewReader("probe:\n  portal: \"<<\"\n"))
	if err != nil {
		t.Fatalf("decodeConfig() error = %v", err)
	}
	assertOptionalString(t, got.Probe.Portal, "<<")
}

func TestDecodeConfig_rejectsNonStrictYAML(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty document", raw: ``},
		{name: "root null", raw: "null\n"},
		{name: "root sequence", raw: "- item\n"},
		{name: "root string", raw: "config\n"},
		{name: "unknown root key", raw: "unknown: value\n"},
		{name: "unknown nested key", raw: "probe:\n  unknown: value\n"},
		{name: "null section", raw: "auth:\n"},
		{name: "string section", raw: "auth: config\n"},
		{name: "sequence section", raw: "serve:\n  - item\n"},
		{name: "null field", raw: "serve:\n  listen:\n"},
		{name: "number field", raw: "serve:\n  listen: 1080\n"},
		{name: "float field", raw: "serve:\n  listen: 10.80\n"},
		{name: "boolean field", raw: "auth:\n  browser: true\n"},
		{name: "tilde null field", raw: "auth:\n  browser: ~\n"},
		{name: "timestamp field", raw: "auth:\n  timeout: 2026-08-09\n"},
		{name: "sequence field", raw: "probe:\n  portal: []\n"},
		{name: "mapping field", raw: "probe:\n  portal: {}\n"},
		{name: "duplicate root key", raw: "probe: {}\nprobe: {}\n"},
		{name: "duplicate nested key", raw: "serve:\n  listen: one\n  listen: two\n"},
		{name: "case variant root key", raw: "Log_Level: debug\n"},
		{name: "case variant nested key", raw: "probe:\n  Portal: https://vpn.example.test\n"},
		{name: "non-string key", raw: "? [probe]\n: {}\n"},
		{name: "anchor", raw: "log_level: &level debug\n"},
		{name: "section anchor", raw: "serve: &base\n  listen: 127.0.0.1:1080\n"},
		{name: "alias", raw: "log_level: &level debug\nprobe:\n  host_id: *level\n"},
		{name: "merge key", raw: "serve: &base\n  listen: 127.0.0.1:1080\nauth:\n  <<: *base\n"},
		{name: "merge key without anchor", raw: "auth:\n  <<: {host_id: value}\n"},
		{name: "custom tag", raw: "log_level: !secret error\n"},
		{name: "malformed mapping", raw: "probe:\n portal: value\n  host_id: value\n"},
		{name: "second document", raw: "{}\n---\n{}\n"},
		{name: "empty second document", raw: "{}\n---\n"},
		{name: "trailing scalar", raw: "{}\ntrailing\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeConfig(strings.NewReader(test.raw))
			if err == nil {
				t.Fatal("decodeConfig() error = nil, want strict YAML rejection")
			}
		})
	}
}

func TestLoadConfig_readsSelectedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("probe:\n  host_id: \"from-file\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := loadConfig(path, false)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	assertOptionalString(t, got.Probe.HostID, "from-file")
}

func TestLoadConfig_rejectsMissingExplicitFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := loadConfig(path, false); err == nil {
		t.Fatal("loadConfig() error = nil, want missing explicit file error")
	}
}

func TestLoadConfig_ignoresMissingAutomaticFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	got, err := loadConfig(path, true)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if want := (fileConfig{}); !reflect.DeepEqual(got, want) {
		t.Fatalf("loadConfig() = %#v, want empty config", got)
	}
}

func TestLoadConfig_rejectsNonRegularFile(t *testing.T) {
	if _, err := loadConfig(t.TempDir(), false); err == nil {
		t.Fatal("loadConfig() error = nil, want directory rejection")
	}
}

func TestDecodeConfig_rejectsOversizedInput(t *testing.T) {
	reader := strings.NewReader(strings.Repeat("#", maxConfigBytes+1))
	if _, err := decodeConfig(reader); err == nil {
		t.Fatal("decodeConfig() error = nil, want size limit rejection")
	}
}
