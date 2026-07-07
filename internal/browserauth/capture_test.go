package browserauth

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_artifactFromCandidate_returnsHeaderArtifact_whenHeadersContainACSFields(t *testing.T) {
	// Given
	headers := map[string]string{"Saml-Username": "alice@example.test", "Prelogin-Cookie": "pre-cookie"}

	// When
	got, ok := artifactFromCandidate(headers, "")

	// Then
	if !ok {
		t.Fatal("artifactFromCandidate() did not find artifact")
	}
	if got.PreloginCookie.String() != "pre-cookie" {
		t.Fatalf("PreloginCookie = %q, want pre-cookie", got.PreloginCookie.String())
	}
}

func Test_artifactFromCandidate_returnsBodyArtifact_whenHeadersDoNotContainArtifact(t *testing.T) {
	// Given
	body := `<saml-username>alice@example.test</saml-username><prelogin-cookie>pre-cookie</prelogin-cookie>`

	// When
	got, ok := artifactFromCandidate(map[string]string{}, body)

	// Then
	if !ok {
		t.Fatal("artifactFromCandidate() did not find artifact")
	}
	if got.Username != "alice@example.test" {
		t.Fatalf("Username = %q, want alice@example.test", got.Username)
	}
}

func Test_artifactFromEventURL_returnsCallbackArtifact_whenURLContainsGlobalProtectCallback(t *testing.T) {
	// Given
	event := responseEvent{url: "globalprotectcallback:cas-as=1&un=alice&token=callback-token"}

	// When
	got, ok := artifactFromEventURL(event)

	// Then
	if !ok {
		t.Fatal("artifactFromEventURL() did not find artifact")
	}
	if got.Kind != gp.ArtifactCAS {
		t.Fatalf("Kind = %q, want %q", got.Kind, gp.ArtifactCAS)
	}
	if got.Token.String() != "callback-token" {
		t.Fatalf("Token = %q, want callback-token", got.Token.String())
	}
}

func Test_artifactFromEventLocation_returnsCallbackArtifact_whenLocationContainsGlobalProtectCallback(t *testing.T) {
	// Given
	event := responseEvent{headers: map[string]string{"Location": "globalprotectcallback:/cas-as=1&un=alice&token=callback-token"}}

	// When
	got, ok := artifactFromEventLocation(event)

	// Then
	if !ok {
		t.Fatal("artifactFromEventLocation() did not find artifact")
	}
	if got.Token.String() != "callback-token" {
		t.Fatalf("Token = %q, want callback-token", got.Token.String())
	}
}

func Test_collectArtifacts_returnsCallbackArtifact_fromRequestURL(t *testing.T) {
	// Given
	events := make(chan responseEvent, 1)
	results := make(chan captureResult, 1)
	events <- responseEvent{id: "req-1", url: "globalprotectcallback:cas-as=1&un=alice&token=callback-token"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// When
	go collectArtifacts(ctx, context.Background(), events, results, emptyResponseBody)

	// Then
	result := waitForResult(t, results)
	if result.artifact.Token.String() != "callback-token" {
		t.Fatalf("Token = %q, want callback-token", result.artifact.Token.String())
	}
}

func Test_listenForResponses_sendsRequestURLAndRedirectLocation(t *testing.T) {
	// Given
	events := make(chan responseEvent, 2)
	results := make(chan captureResult, 1)
	listener := listenForResponses(events, results)

	// When
	listener(&network.EventRequestWillBeSent{
		RequestID: "req-1",
		Request:   &network.Request{URL: "globalprotectcallback:cas-as=1&un=alice&token=request-token"},
	})
	listener(&network.EventRequestWillBeSent{
		RequestID:        "req-2",
		RedirectResponse: &network.Response{Headers: network.Headers{"Location": "globalprotectcallback:/cas-as=1&un=alice&token=redirect-token"}},
	})

	// Then
	artifacts := collectEventArtifacts(t, events, 2)
	if artifacts["request-token"] != gp.ArtifactCAS {
		t.Fatalf("request callback artifact missing; got %#v", artifacts)
	}
	if artifacts["redirect-token"] != gp.ArtifactCAS {
		t.Fatalf("redirect callback artifact missing; got %#v", artifacts)
	}
}

func Test_listenForResponses_reportsOverflow_whenChannelFull(t *testing.T) {
	// Given
	events := make(chan responseEvent, 1)
	events <- responseEvent{id: "filler"}
	results := make(chan captureResult, 1)
	listener := listenForResponses(events, results)

	// When
	listener(&network.EventRequestWillBeSent{
		RequestID: "req-1",
		Request:   &network.Request{URL: "globalprotectcallback:cas-as=1&un=alice&token=callback-token"},
	})

	// Then
	result := waitForResult(t, results)
	if !errors.Is(result.err, errCaptureEventOverflow) {
		t.Fatalf("result error = %v, want errCaptureEventOverflow", result.err)
	}
}

func Test_collectArtifacts_keepsFinishedEvent_whenItArrivesBeforeResponse(t *testing.T) {
	// Given
	events := make(chan responseEvent, 2)
	results := make(chan captureResult, 1)
	events <- responseEvent{id: "req-1", finished: true}
	events <- responseEvent{id: "req-1", headers: map[string]string{"Content-Type": "text/html"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readBody := func(_ context.Context, id network.RequestID) (string, error) {
		if id != "req-1" {
			t.Fatalf("request id = %q, want req-1", id)
		}
		return `<saml-username>alice@example.test</saml-username><prelogin-cookie>pre-cookie</prelogin-cookie>`, nil
	}

	// When
	go collectArtifacts(ctx, context.Background(), events, results, readBody)

	// Then
	result := waitForResult(t, results)
	if result.artifact.PreloginCookie.String() != "pre-cookie" {
		t.Fatalf("PreloginCookie = %q, want pre-cookie", result.artifact.PreloginCookie.String())
	}
}

func Test_navigationURL_writesPostHTML_toTempFileURL(t *testing.T) {
	// Given
	html := `<html><form method="POST"><input name="SAMLRequest" value="secret-saml-request"></form></html>`
	request, err := gp.NewSAMLRequest(html)
	if err != nil {
		t.Fatalf("NewSAMLRequest() error = %v", err)
	}
	prelogin := gp.Prelogin{AuthMode: gp.AuthModeSAML, SAMLMethod: gp.SAMLPost, SAMLRequest: request}
	profileDir := t.TempDir()

	// When
	got, err := navigationURL(prelogin, profileDir)

	// Then
	if err != nil {
		t.Fatalf("navigationURL() error = %v", err)
	}
	if !strings.HasPrefix(got, "file://") {
		t.Fatalf("navigation URL = %q, want file URL", got)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.Host != "" {
		t.Fatalf("file URL host = %q, want empty host", parsed.Host)
	}
	if strings.Contains(got, "secret-saml-request") || strings.Contains(got, html) {
		t.Fatalf("navigation URL leaked SAML HTML: %q", got)
	}
	written, err := os.ReadFile(filepath.Join(profileDir, "sso.html"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(written) != html {
		t.Fatalf("sso.html = %q, want html", string(written))
	}
}

func Test_fileURL_formatsWindowsDrivePath_withoutHost(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows drive-letter path semantics")
	}
	// Given
	path := `C:\Temp\gp socks\sso.html`

	// When
	got := fileURL(path)

	// Then
	if got != "file:///C:/Temp/gp%20socks/sso.html" {
		t.Fatalf("fileURL() = %q, want file:///C:/Temp/gp%%20socks/sso.html", got)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.Host != "" {
		t.Fatalf("Host = %q, want empty", parsed.Host)
	}
}

func emptyResponseBody(context.Context, network.RequestID) (string, error) {
	return "", nil
}

func waitForResult(t *testing.T, results <-chan captureResult) captureResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(time.Second):
		t.Fatal("collectArtifacts() did not emit artifact")
		return captureResult{}
	}
}

func waitForEvent(t *testing.T, events <-chan responseEvent) responseEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatal("listener did not emit event")
		return responseEvent{}
	}
}

func collectEventArtifacts(t *testing.T, events <-chan responseEvent, count int) map[string]gp.ArtifactKind {
	t.Helper()
	artifacts := map[string]gp.ArtifactKind{}
	for range count {
		event := waitForEvent(t, events)
		if artifact, ok := artifactFromEventURL(event); ok {
			artifacts[artifact.Token.String()] = artifact.Kind
		}
		if artifact, ok := artifactFromEventLocation(event); ok {
			artifacts[artifact.Token.String()] = artifact.Kind
		}
	}
	return artifacts
}
