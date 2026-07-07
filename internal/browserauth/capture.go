package browserauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

const defaultCaptureTimeout = 5 * time.Minute

var errCaptureEventOverflow = errors.New("browserauth: capture event queue overflow")

type responseEvent struct {
	id       network.RequestID
	url      string
	headers  map[string]string
	finished bool
	failed   bool
}

type captureResult struct {
	artifact gp.AuthArtifact
	err      error
}

type responseBodyReader func(context.Context, network.RequestID) (string, error)

func (c Capturer) Capture(ctx context.Context, request Request) (gp.AuthArtifact, error) {
	if request.Prelogin.AuthMode != gp.AuthModeSAML || request.Prelogin.SAMLRequest.String() == "" {
		return gp.AuthArtifact{}, fmt.Errorf("browser auth prelogin: %w", gp.ErrInvalidPrelogin)
	}
	browserPath, err := c.finder.find(request.Browser, request.BrowserPath)
	if err != nil {
		return gp.AuthArtifact{}, err
	}
	profileDir, err := osMkdirTemp("", "gp-socks-browser-*")
	if err != nil {
		return gp.AuthArtifact{}, fmt.Errorf("create browser profile: %w", err)
	}
	defer osRemoveAll(profileDir)

	target, err := navigationURL(request.Prelogin, profileDir)
	if err != nil {
		return gp.AuthArtifact{}, err
	}
	captureCtx, cancel := context.WithTimeout(ctx, captureTimeout(request.Timeout))
	defer cancel()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(browserPath),
		chromedp.UserDataDir(profileDir),
		chromedp.Flag("headless", false),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(captureCtx, opts...)
	defer allocCancel()
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	events := make(chan responseEvent, 128)
	results := make(chan captureResult, 1)
	listenCtx, listenCancel := context.WithCancel(browserCtx)
	defer listenCancel()
	chromedp.ListenTarget(listenCtx, listenForResponses(events, results))
	go collectArtifacts(listenCtx, browserCtx, events, results, readResponseBody)

	if err := chromedp.Run(browserCtx, network.Enable(), chromedp.Navigate(target)); err != nil {
		return gp.AuthArtifact{}, fmt.Errorf("start browser auth: %w", err)
	}
	select {
	case result := <-results:
		if result.err != nil {
			return gp.AuthArtifact{}, result.err
		}
		return result.artifact, nil
	case <-captureCtx.Done():
		return gp.AuthArtifact{}, fmt.Errorf("capture auth artifact: %w", captureCtx.Err())
	}
}

func listenForResponses(events chan<- responseEvent, results chan<- captureResult) func(any) {
	return func(ev any) {
		switch event := ev.(type) {
		case *network.EventRequestWillBeSent:
			requestURL := ""
			if event.Request != nil {
				requestURL = event.Request.URL
			}
			headers := map[string]string{}
			if event.RedirectResponse != nil {
				headers = stringHeaders(event.RedirectResponse.Headers)
			}
			sendEvent(events, results, responseEvent{id: event.RequestID, url: requestURL, headers: headers})
		case *network.EventResponseReceived:
			if event.Response == nil {
				return
			}
			response := responseEvent{id: event.RequestID, url: event.Response.URL, headers: stringHeaders(event.Response.Headers)}
			sendEvent(events, results, response)
		case *network.EventLoadingFinished:
			sendEvent(events, results, responseEvent{id: event.RequestID, finished: true})
		case *network.EventLoadingFailed:
			sendEvent(events, results, responseEvent{id: event.RequestID, url: event.ErrorText, failed: true})
		}
	}
}

func sendEvent(events chan<- responseEvent, results chan<- captureResult, event responseEvent) {
	select {
	case events <- event:
	default:
		sendOverflow(results)
	}
}

func sendOverflow(results chan<- captureResult) {
	select {
	case results <- captureResult{err: errCaptureEventOverflow}:
	default:
	}
}

func collectArtifacts(ctx context.Context, browserCtx context.Context, events <-chan responseEvent, results chan<- captureResult, readBody responseBodyReader) {
	pending := map[network.RequestID]map[string]string{}
	finished := map[network.RequestID]struct{}{}
	for {
		select {
		case event := <-events:
			if artifact, ok := artifactFromEventURL(event); ok {
				sendResult(ctx, results, captureResult{artifact: artifact})
				return
			}
			if event.finished || event.failed {
				finished[event.id] = struct{}{}
				if headers, ok := pending[event.id]; ok {
					delete(pending, event.id)
					delete(finished, event.id)
					if artifact, ok := artifactFromResponseBody(browserCtx, readBody, event.id, headers); ok {
						sendResult(ctx, results, captureResult{artifact: artifact})
						return
					}
				}
				continue
			}
			if artifact, ok := artifactFromCandidate(event.headers, ""); ok {
				sendResult(ctx, results, captureResult{artifact: artifact})
				return
			}
			if artifact, ok := artifactFromEventLocation(event); ok {
				sendResult(ctx, results, captureResult{artifact: artifact})
				return
			}
			if _, ok := finished[event.id]; ok {
				delete(finished, event.id)
				if artifact, ok := artifactFromResponseBody(browserCtx, readBody, event.id, event.headers); ok {
					sendResult(ctx, results, captureResult{artifact: artifact})
					return
				}
				continue
			}
			pending[event.id] = event.headers
		case <-ctx.Done():
			return
		}
	}
}

func artifactFromResponseBody(ctx context.Context, readBody responseBodyReader, id network.RequestID, headers map[string]string) (gp.AuthArtifact, bool) {
	body, err := readBody(ctx, id)
	if err != nil {
		return gp.AuthArtifact{}, false
	}
	return artifactFromCandidate(headers, body)
}

func readResponseBody(ctx context.Context, id network.RequestID) (string, error) {
	body, err := network.GetResponseBody(id).Do(ctx)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func artifactFromEventURL(event responseEvent) (gp.AuthArtifact, bool) {
	return artifactFromRawCallback(event.url)
}

func artifactFromEventLocation(event responseEvent) (gp.AuthArtifact, bool) {
	return artifactFromRawCallback(headerValue(event.headers, "location"))
}

func artifactFromRawCallback(raw string) (gp.AuthArtifact, bool) {
	start := strings.Index(raw, "globalprotectcallback:")
	if start < 0 {
		return gp.AuthArtifact{}, false
	}
	artifact, err := gp.ParseAuthArtifact(raw[start:])
	return artifact, err == nil
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func artifactFromCandidate(headers map[string]string, body string) (gp.AuthArtifact, bool) {
	artifact, err := gp.ParseAuthResponse(headers, body)
	return artifact, err == nil
}

func stringHeaders(headers network.Headers) map[string]string {
	converted := make(map[string]string, len(headers))
	for name, value := range headers {
		converted[name] = fmt.Sprint(value)
	}
	return converted
}

func navigationURL(prelogin gp.Prelogin, profileDir string) (string, error) {
	raw := strings.TrimSpace(prelogin.SAMLRequest.String())
	switch prelogin.SAMLMethod {
	case gp.SAMLPost:
		return writePostHTML(profileDir, raw)
	case gp.SAMLRedirect:
		return raw, nil
	default:
		return "", fmt.Errorf("saml method %s: %w", prelogin.SAMLMethod, gp.ErrInvalidPrelogin)
	}
}

func writePostHTML(profileDir string, html string) (string, error) {
	path := filepath.Join(profileDir, "sso.html")
	if err := osWriteFile(path, []byte(html), 0o600); err != nil {
		return "", fmt.Errorf("write saml post html: %w", err)
	}
	return fileURL(path), nil
}

func fileURL(path string) string {
	urlPath := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}
	return (&url.URL{Scheme: "file", Path: urlPath}).String()
}

func sendResult(ctx context.Context, results chan<- captureResult, result captureResult) {
	select {
	case results <- result:
	case <-ctx.Done():
	}
}

func captureTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return defaultCaptureTimeout
}
