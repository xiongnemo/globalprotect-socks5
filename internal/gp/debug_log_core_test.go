package gp

import (
	"strings"
	"testing"
)

func Test_RedactedSnippet_redactsSensitiveAssignmentsBeforeTruncating(t *testing.T) {
	// Given
	body := []byte(`prefix authorization=BearerToken token="secret-token" {"authcookie":"secret-cookie"} <input value="secret-password" name="password"> Bearer secret-bearer ` + strings.Repeat("x", debugResponseSnippetBytes))

	// When
	snippet := redactedSnippet(body)

	// Then
	for _, secret := range []string{"BearerToken", "secret-token", "secret-cookie", "secret-password", "secret-bearer"} {
		if strings.Contains(snippet, secret) {
			t.Fatalf("snippet leaked %q: %q", secret, snippet)
		}
	}
	if !strings.Contains(snippet, redactedValue) {
		t.Fatalf("snippet = %q, want redaction marker", snippet)
	}
	if len(snippet) > debugResponseSnippetBytes {
		t.Fatalf("snippet length = %d, want <= %d", len(snippet), debugResponseSnippetBytes)
	}
}
