package gp

import (
	"net/url"
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

func Test_RedactedSnippet_redactsEncodedSensitiveRequestValuesInGenericText(t *testing.T) {
	// Given
	secret := `secret+cookie&<value>`
	values := sensitiveFormValues(url.Values{"prelogin-cookie": {secret}})
	body := []byte(`generic raw ` + secret + ` encoded ` + url.QueryEscape(secret) + ` html secret+cookie&amp;&lt;value&gt;`)

	// When
	snippet := redactedSnippet(body, values...)

	// Then
	if strings.Contains(snippet, "secret+cookie") || strings.Contains(snippet, "secret%2Bcookie") {
		t.Fatalf("snippet leaked encoded request secret: %q", snippet)
	}
	if !strings.Contains(snippet, redactedValue) {
		t.Fatalf("snippet = %q, want redaction marker", snippet)
	}
}
