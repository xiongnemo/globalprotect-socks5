package app

import "testing"

func TestSelectConfig_usesDefaultPath_whenAutoConfigEnabled(t *testing.T) {
	got, err := selectConfig(optionalString{}, false, true)
	if err != nil {
		t.Fatalf("selectConfig() error = %v", err)
	}
	if got.path != defaultConfigPath || !got.allowMissing {
		t.Fatalf("selectConfig() = %#v, want optional %q", got, defaultConfigPath)
	}
}

func TestSelectConfig_returnsExplicitPath_withoutAutoFallback(t *testing.T) {
	cliPath := testOptionalString("relative/custom.yaml")
	got, err := selectConfig(cliPath, false, true)
	if err != nil {
		t.Fatalf("selectConfig() error = %v", err)
	}
	if got.path != cliPath.value || got.allowMissing {
		t.Fatalf("selectConfig() = %#v, want required explicit path", got)
	}
}

func TestSelectConfig_returnsDisabled_whenNoConfigSelected(t *testing.T) {
	got, err := selectConfig(optionalString{}, true, true)
	if err != nil {
		t.Fatalf("selectConfig() error = %v", err)
	}
	if got.path != "" {
		t.Fatalf("selectConfig() = %#v, want disabled file layer", got)
	}
}

func TestSelectConfig_returnsDisabled_whenAutoConfigNotEnabled(t *testing.T) {
	got, err := selectConfig(optionalString{}, false, false)
	if err != nil {
		t.Fatalf("selectConfig() error = %v", err)
	}
	if got.path != "" {
		t.Fatalf("selectConfig() = %#v, want no ambient file discovery", got)
	}
}

func TestSelectConfig_rejectsBlankExplicitPath(t *testing.T) {
	if _, err := selectConfig(testOptionalString(" \t "), false, true); err == nil {
		t.Fatal("selectConfig() error = nil, want blank explicit path error")
	}
}

func TestSelectConfig_rejectsExplicitPathWithNoConfig(t *testing.T) {
	if _, err := selectConfig(testOptionalString("custom.yaml"), true, true); err == nil {
		t.Fatal("selectConfig() error = nil, want mutually exclusive root flags")
	}
}
