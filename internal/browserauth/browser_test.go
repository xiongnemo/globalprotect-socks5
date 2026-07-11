package browserauth

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/chromedp/cdproto/network"
)

func Test_ParseBrowser_returnsAuto_whenInputEmpty(t *testing.T) {
	// Given
	raw := ""

	// When
	got, err := ParseBrowser(raw)

	// Then
	if err != nil {
		t.Fatalf("ParseBrowser() error = %v", err)
	}
	if got != BrowserAuto {
		t.Fatalf("Browser = %q, want %q", got, BrowserAuto)
	}
}

func Test_browserFinder_find_usesOverride_whenPathExists(t *testing.T) {
	// Given
	const override = `C:\Tools\Chrome\chrome.exe`
	finder := browserFinder{
		lookupPath: func(name string) (string, error) { t.Fatalf("lookupPath(%q) was called", name); return "", nil },
		exists:     func(path string) bool { return path == override },
	}

	// When
	got, err := finder.find(BrowserAuto, override)

	// Then
	if err != nil {
		t.Fatalf("find() error = %v", err)
	}
	if got != override {
		t.Fatalf("path = %q, want %q", got, override)
	}
}

func Test_browserFinder_find_returnsEdgeCandidate_whenBrowserEdgeRequested(t *testing.T) {
	// Given
	finder := browserFinder{
		lookupPath: func(name string) (string, error) {
			if name == "msedge" {
				return "/usr/bin/msedge", nil
			}
			return "", errors.New("not found")
		},
		exists: func(string) bool { return false },
		candidates: []browserCandidate{
			{browser: BrowserChrome, names: []string{"chrome"}},
			{browser: BrowserEdge, names: []string{"msedge"}},
		},
	}

	// When
	got, err := finder.find(BrowserEdge, "")

	// Then
	if err != nil {
		t.Fatalf("find() error = %v", err)
	}
	if got != "/usr/bin/msedge" {
		t.Fatalf("path = %q, want /usr/bin/msedge", got)
	}
}

func Test_stringHeaders_convertsCDPHeaderValues(t *testing.T) {
	// Given
	headers := network.Headers{"Saml-Username": "alice@example.test", "Retry-After": 5}

	// When
	got := stringHeaders(headers)

	// Then
	if got["Retry-After"] != "5" {
		t.Fatalf("Retry-After = %q, want 5", got["Retry-After"])
	}
}

func Test_cdprotoIPAddressSpace_acceptsLoopback_whenChromeEmitsNewEnum(t *testing.T) {
	// Given
	input := []byte(`"Loopback"`)

	// When
	var got network.IPAddressSpace
	err := json.Unmarshal(input, &got)

	// Then
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got != network.IPAddressSpaceLoopback {
		t.Fatalf("IPAddressSpace = %q, want %q", got, network.IPAddressSpaceLoopback)
	}
}
