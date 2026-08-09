package app

import "testing"

func TestParseLogLevel_acceptsSupportedLevels_whenInputCanonical(t *testing.T) {
	// Given
	levels := []string{"error", "warn", "info", "debug"}

	for _, raw := range levels {
		t.Run(raw, func(t *testing.T) {
			// When
			_, err := parseLogLevel(raw)

			// Then
			if err != nil {
				t.Fatalf("parseLogLevel(%q) error = %v", raw, err)
			}
		})
	}
}

func TestParseLogLevel_normalizesCaseAndWhitespace_whenInputSupported(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		canonical string
	}{
		{name: "error", raw: "  ERROR\t", canonical: "error"},
		{name: "warn", raw: "\nWaRn ", canonical: "warn"},
		{name: "info", raw: " Info ", canonical: "info"},
		{name: "debug", raw: "\tDeBuG\r\n", canonical: "debug"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			want := mustParseLogLevel(t, test.canonical)

			// When
			got, err := parseLogLevel(test.raw)

			// Then
			if err != nil {
				t.Fatalf("parseLogLevel(%q) error = %v", test.raw, err)
			}
			if got != want {
				t.Fatalf("parseLogLevel(%q) = %v, want canonical %q", test.raw, got, test.canonical)
			}
		})
	}
}

func TestParseLogLevel_rejectsInput_whenBlankUnknownOrNumeric(t *testing.T) {
	// Given
	inputs := []string{"", " \t\r\n ", "trace", "warning", "0", "-4", "8"}

	for _, raw := range inputs {
		t.Run(raw, func(t *testing.T) {
			// When
			_, err := parseLogLevel(raw)

			// Then
			if err == nil {
				t.Fatalf("parseLogLevel(%q) error = nil, want rejection", raw)
			}
		})
	}
}
