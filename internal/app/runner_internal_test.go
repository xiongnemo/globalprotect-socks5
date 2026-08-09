package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
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

func Test_NewRunner_isEnvironmentNeutral_whenLookupEnvOmitted(t *testing.T) {
	// Given
	ambient := map[string]string{
		envLogLevel:          "debug",
		envListen:            "127.0.0.1:2222",
		envPortal:            "https://ambient.example.test",
		envGateway:           "https://ambient-gateway.example.test",
		envHostID:            "ambient-host",
		envBrowser:           "edge",
		envBrowserPath:       "AMBIENT_BROWSER_PATH",
		envBrowserProfileDir: "AMBIENT_PROFILE_PATH",
		envTimeout:           "17s",
		envSSOFile:           "AMBIENT_SSO_PATH",
		envDebugLog:          "AMBIENT_DEBUG_PATH",
	}
	for name, value := range ambient {
		t.Setenv(name, value)
	}
	runner := NewRunner(IO{})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var applicationLog bytes.Buffer
	runner.io.Stdout = &stdout
	runner.io.Stderr = &stderr
	runner.io.LogWriter = &applicationLog
	for name := range ambient {
		if value, present := runner.io.LookupEnv(name); present || value != "" {
			t.Errorf("bare runner LookupEnv(%q) = (%q, %t), want environment-neutral absence", name, value, present)
		}
	}

	// When
	err := runner.Run(context.Background(), []string{
		"parse-auth", "globalprotectcallback:cas-as=1&un=alice&token=secret-token",
	})

	// Then
	if err != nil {
		t.Fatalf("Run() error = %v, want defaults independent of ambient environment", err)
	}
	if !strings.Contains(stdout.String(), "kind=cas username=alice") {
		t.Fatalf("stdout = %q, want parsed artifact summary", stdout.String())
	}
	if applicationLog.Len() != 0 {
		t.Fatalf("application log = %q, want default error-level behavior", applicationLog.String())
	}
}

func Test_NewRunner_usesInjectedStderrForApplicationRecords_whenLogWriterOmitted(t *testing.T) {
	// Given
	var stderr bytes.Buffer
	runner := NewRunner(IO{
		Stdout:    io.Discard,
		Stderr:    &stderr,
		LookupEnv: func(string) (string, bool) { return "", false },
	})

	// When
	err := runner.Run(context.Background(), []string{"parse-auth", "invalid-artifact"})

	// Then
	if err == nil {
		t.Fatal("Run() error = nil, want parse failure")
	}
	if !strings.Contains(stderr.String(), `"msg":"command failed"`) {
		t.Fatalf("injected stderr = %q, want application failure record", stderr.String())
	}
}
