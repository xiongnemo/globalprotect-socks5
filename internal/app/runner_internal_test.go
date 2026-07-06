package app

import (
	"net/http"
	"testing"
)

func Test_NewRunner_setsBoundedHTTPTimeout_whenHTTPClientMissing(t *testing.T) {
	// Given
	runner := NewRunner(IO{})

	// When
	got := runner.io.HTTPClient.Timeout

	// Then
	if got != defaultHTTPTimeout {
		t.Fatalf("HTTP timeout = %s, want %s", got, defaultHTTPTimeout)
	}
}

func Test_NewRunner_preservesHTTPClient_whenProvided(t *testing.T) {
	// Given
	client := &http.Client{}

	// When
	runner := NewRunner(IO{HTTPClient: client})

	// Then
	if runner.io.HTTPClient != client {
		t.Fatal("NewRunner replaced provided HTTP client")
	}
}
