package browserauth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

type recordingBrowserRunner struct {
	artifact gp.AuthArtifact
	requests []browserRunRequest
}

func (r *recordingBrowserRunner) run(_ context.Context, request browserRunRequest) (gp.AuthArtifact, error) {
	r.requests = append(r.requests, request)
	return r.artifact, nil
}

func (r *recordingBrowserRunner) onlyRequest(t *testing.T) browserRunRequest {
	t.Helper()
	if len(r.requests) != 1 {
		t.Fatalf("capture runs = %d, want 1", len(r.requests))
	}
	return r.requests[0]
}

func testCapturer(runner *recordingBrowserRunner) Capturer {
	return Capturer{
		finder: browserFinder{
			lookupPath: func(string) (string, error) { return "", errors.New("not found") },
			exists:     func(path string) bool { return path == testBrowserPath },
		},
		runner: runner.run,
	}
}

func testCaptureRequest(t *testing.T, profileDir string) Request {
	t.Helper()
	samlRequest, err := gp.NewSAMLRequest("https://portal.example.test/saml")
	if err != nil {
		t.Fatalf("NewSAMLRequest() error = %v", err)
	}
	return Request{
		Prelogin:    gp.Prelogin{AuthMode: gp.AuthModeSAML, SAMLMethod: gp.SAMLRedirect, SAMLRequest: samlRequest},
		Browser:     BrowserChrome,
		BrowserPath: testBrowserPath,
		ProfileDir:  profileDir,
	}
}

func testCaptureArtifact(t *testing.T) gp.AuthArtifact {
	t.Helper()
	token, err := gp.NewSecret("callback-token")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	return gp.AuthArtifact{Kind: gp.ArtifactCAS, Username: "alice@example.test", Token: token}
}

func defaultBrowserProfileRoots(root string) []string {
	return []string{
		filepath.Join(root, "home", ".config", "google-chrome"),
		filepath.Join(root, "home", "Library", "Application Support", "Google", "Chrome"),
		filepath.Join(root, "local-app-data", "Google", "Chrome", "User Data"),
		filepath.Join(root, "xdg-config", "google-chrome"),
	}
}

const testBrowserPath = "/browser/bin/chrome"
