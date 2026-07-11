package browserauth

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

const defaultCaptureTimeout = 5 * time.Minute

type browserRunner func(context.Context, browserRunRequest) (gp.AuthArtifact, error)

type browserRunRequest struct {
	browserPath string
	profileDir  string
	target      string
	timeout     time.Duration
}

func runBrowserCapture(ctx context.Context, request browserRunRequest) (gp.AuthArtifact, error) {
	captureCtx, cancel := context.WithTimeout(ctx, captureTimeout(request.timeout))
	defer cancel()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(request.browserPath),
		chromedp.UserDataDir(request.profileDir),
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

	if err := chromedp.Run(browserCtx, network.Enable(), chromedp.Navigate(request.target)); err != nil {
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

func captureTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return defaultCaptureTimeout
}
