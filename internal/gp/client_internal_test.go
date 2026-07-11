package gp

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func Test_NewClient_copiesHTTPClient_withoutMutatingCaller(t *testing.T) {
	// Given
	httpClient := &http.Client{Timeout: time.Second}

	// When
	client := NewClient(httpClient, ClientProfile{})
	httpClient.Timeout = 2 * time.Second

	// Then
	if httpClient.Jar != nil {
		t.Fatal("caller HTTP client Jar was mutated")
	}
	if client.httpClient.Timeout != time.Second {
		t.Fatalf("client HTTP timeout = %s, want %s", client.httpClient.Timeout, time.Second)
	}
	if client.httpClient.Jar == nil {
		t.Fatal("client HTTP Jar = nil, want private in-memory jar")
	}
}

func Test_NewClient_preservesCallerSuppliedJar(t *testing.T) {
	// Given
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	httpClient := &http.Client{Jar: jar}

	// When
	client := NewClient(httpClient, ClientProfile{})

	// Then
	if client.httpClient.Jar != jar {
		t.Fatal("client HTTP Jar does not preserve caller-supplied jar")
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
