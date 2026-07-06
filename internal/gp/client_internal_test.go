package gp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test_NewClient_setsBoundedHTTPTimeout_whenHTTPClientMissing(t *testing.T) {
	// Given
	client := NewClient(nil, ClientProfile{})

	// When
	got := client.httpClient.Timeout

	// Then
	if got != defaultHTTPTimeout {
		t.Fatalf("HTTP timeout = %s, want %s", got, defaultHTTPTimeout)
	}
}

func Test_NewClient_preservesHTTPClient_whenProvided(t *testing.T) {
	// Given
	httpClient := &http.Client{}

	// When
	client := NewClient(httpClient, ClientProfile{})

	// Then
	if client.httpClient != httpClient {
		t.Fatal("NewClient replaced provided HTTP client")
	}
}

func Test_Client_Prelogin_rejectsResponse_whenBodyExceedsLimit(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxPreloginResponseBytes+1)))
	}))
	defer server.Close()
	portal, err := NewPortalURL(server.URL)
	if err != nil {
		t.Fatalf("NewPortalURL() error = %v", err)
	}
	client := NewClient(server.Client(), ClientProfile{})

	// When
	_, err = client.Prelogin(context.Background(), portal)

	// Then
	if !errors.Is(err, ErrInvalidPrelogin) {
		t.Fatalf("Prelogin() error = %v, want ErrInvalidPrelogin", err)
	}
}
