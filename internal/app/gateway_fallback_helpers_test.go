package app_test

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

type gatewayFallbackAuthCapturer struct {
	mu        sync.Mutex
	artifacts []gp.AuthArtifact
	next      int
	requests  chan browserauth.Request
}

func newGatewayFallbackAuthCapturer(artifacts ...gp.AuthArtifact) *gatewayFallbackAuthCapturer {
	return &gatewayFallbackAuthCapturer{artifacts: artifacts, requests: make(chan browserauth.Request, len(artifacts))}
}

func (capturer *gatewayFallbackAuthCapturer) Capture(_ context.Context, request browserauth.Request) (gp.AuthArtifact, error) {
	capturer.mu.Lock()
	defer capturer.mu.Unlock()
	if capturer.next >= len(capturer.artifacts) {
		return gp.AuthArtifact{}, fmt.Errorf("unexpected auth capture %d", capturer.next+1)
	}
	artifact := capturer.artifacts[capturer.next]
	capturer.next++
	capturer.requests <- request
	return artifact, nil
}

func (capturer *gatewayFallbackAuthCapturer) waitRequests(t *testing.T, count int) []browserauth.Request {
	t.Helper()
	requests := make([]browserauth.Request, 0, count)
	timeout := time.After(time.Second)
	for len(requests) < count {
		select {
		case request := <-capturer.requests:
			requests = append(requests, request)
		case <-timeout:
			t.Fatalf("auth captures = %d, want %d", len(requests), count)
		}
	}
	return requests
}

func (capturer *gatewayFallbackAuthCapturer) count() int {
	capturer.mu.Lock()
	defer capturer.mu.Unlock()
	return capturer.next
}

type gatewayFallbackEndpointRecorder struct {
	events chan string
}

func newGatewayFallbackEndpointRecorder() *gatewayFallbackEndpointRecorder {
	return &gatewayFallbackEndpointRecorder{events: make(chan string, 8)}
}

func (recorder *gatewayFallbackEndpointRecorder) record(endpoint string) {
	recorder.events <- endpoint
}

func (recorder *gatewayFallbackEndpointRecorder) wait(t *testing.T, count int) []string {
	t.Helper()
	endpoints := make([]string, 0, count)
	timeout := time.After(time.Second)
	for len(endpoints) < count {
		select {
		case endpoint := <-recorder.events:
			endpoints = append(endpoints, endpoint)
		case <-timeout:
			t.Fatalf("endpoints = %#v, want %d events", endpoints, count)
		}
	}
	return endpoints
}

func (recorder *gatewayFallbackEndpointRecorder) drain() []string {
	var endpoints []string
	for {
		select {
		case endpoint := <-recorder.events:
			endpoints = append(endpoints, endpoint)
		default:
			return endpoints
		}
	}
}

func (recorder *gatewayFallbackEndpointRecorder) assertIdle(t *testing.T) {
	t.Helper()
	select {
	case endpoint := <-recorder.events:
		t.Fatalf("unexpected endpoint after command returned: %s", endpoint)
	default:
	}
}

type gatewayLoginCounter struct {
	mu    sync.Mutex
	count int
}

func newGatewayLoginCounter() *gatewayLoginCounter {
	return &gatewayLoginCounter{}
}

func (counter *gatewayLoginCounter) next() int {
	counter.mu.Lock()
	defer counter.mu.Unlock()
	counter.count++
	return counter.count
}

func formKeys(form url.Values) []string {
	keys := make([]string, 0, len(form))
	for key := range form {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
