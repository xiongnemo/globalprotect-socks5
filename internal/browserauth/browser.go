package browserauth

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

var ErrBrowserNotFound = errors.New("browserauth: browser not found")

type Browser string

const (
	BrowserAuto   Browser = "auto"
	BrowserChrome Browser = "chrome"
	BrowserEdge   Browser = "edge"
)

type Request struct {
	Prelogin    gp.Prelogin
	Browser     Browser
	BrowserPath string
	Timeout     time.Duration
}

type Capturer struct {
	finder browserFinder
	runner browserRunner
}

func NewCapturer() Capturer {
	return Capturer{finder: defaultBrowserFinder(), runner: runBrowserCapture}
}

func ParseBrowser(raw string) (Browser, error) {
	switch Browser(strings.ToLower(strings.TrimSpace(raw))) {
	case "", BrowserAuto:
		return BrowserAuto, nil
	case BrowserChrome:
		return BrowserChrome, nil
	case BrowserEdge:
		return BrowserEdge, nil
	default:
		return "", fmt.Errorf("browser %q: %w", raw, ErrBrowserNotFound)
	}
}

type browserFinder struct {
	lookupPath func(string) (string, error)
	exists     func(string) bool
	candidates []browserCandidate
}

type browserCandidate struct {
	browser Browser
	names   []string
	paths   []string
}

func defaultBrowserFinder() browserFinder {
	return browserFinder{lookupPath: exec.LookPath, exists: executableExists, candidates: defaultBrowserCandidates()}
}

func (f browserFinder) find(browser Browser, override string) (string, error) {
	override = strings.TrimSpace(override)
	if override != "" {
		if f.exists(override) {
			return override, nil
		}
		return "", fmt.Errorf("browser path %s: %w", override, ErrBrowserNotFound)
	}
	for _, candidate := range f.candidates {
		if browser != BrowserAuto && candidate.browser != browser {
			continue
		}
		if path, ok := f.findCandidate(candidate); ok {
			return path, nil
		}
	}
	return "", fmt.Errorf("browser %s: %w", browser, ErrBrowserNotFound)
}

func (f browserFinder) findCandidate(candidate browserCandidate) (string, bool) {
	for _, name := range candidate.names {
		path, err := f.lookupPath(name)
		if err == nil {
			return path, true
		}
	}
	for _, path := range candidate.paths {
		if f.exists(path) {
			return path, true
		}
	}
	return "", false
}

func executableExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func defaultBrowserCandidates() []browserCandidate {
	switch runtime.GOOS {
	case "windows":
		return windowsBrowserCandidates()
	case "darwin":
		return darwinBrowserCandidates()
	default:
		return linuxBrowserCandidates()
	}
}

func windowsBrowserCandidates() []browserCandidate {
	programFiles := os.Getenv("PROGRAMFILES")
	programFilesX86 := os.Getenv("PROGRAMFILES(X86)")
	localAppData := os.Getenv("LOCALAPPDATA")
	return []browserCandidate{
		{browser: BrowserChrome, names: []string{"chrome", "chrome.exe"}, paths: compactPaths(
			filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(programFilesX86, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(localAppData, "Google", "Chrome", "Application", "chrome.exe"),
		)},
		{browser: BrowserEdge, names: []string{"msedge", "msedge.exe"}, paths: compactPaths(
			filepath.Join(programFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(localAppData, "Microsoft", "Edge", "Application", "msedge.exe"),
		)},
	}
}

func darwinBrowserCandidates() []browserCandidate {
	return []browserCandidate{
		{browser: BrowserChrome, names: []string{"google-chrome", "chrome"}, paths: []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}},
		{browser: BrowserEdge, names: []string{"microsoft-edge", "msedge"}, paths: []string{"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"}},
	}
}

func linuxBrowserCandidates() []browserCandidate {
	return []browserCandidate{
		{browser: BrowserChrome, names: []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"}},
		{browser: BrowserEdge, names: []string{"microsoft-edge", "microsoft-edge-stable", "msedge"}},
	}
}

func compactPaths(paths ...string) []string {
	kept := make([]string, 0, len(paths))
	for _, path := range paths {
		if strings.TrimSpace(path) != "" {
			kept = append(kept, path)
		}
	}
	return kept
}
