package browserauth

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

type browserRuntimeConfig struct {
	browserPath string
	profileDir  string
}

type runtimeCaptureRequest struct {
	target  string
	timeout time.Duration
}

type browserRuntime interface {
	capture(context.Context, runtimeCaptureRequest) (gp.AuthArtifact, error)
	close() error
}

type browserRuntimeFactory func(context.Context, browserRuntimeConfig) (browserRuntime, error)

type chromedpRuntime struct {
	browserCtx    context.Context
	browserCancel context.CancelFunc
	allocCancel   context.CancelFunc
}

func newChromedpRuntime(ctx context.Context, config browserRuntimeConfig) (browserRuntime, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("start browser runtime: %w", err)
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(config.browserPath),
		chromedp.UserDataDir(config.profileDir),
		chromedp.Flag("headless", false),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	if err := chromedp.Run(browserCtx); err != nil {
		browserCancel()
		allocCancel()
		return nil, fmt.Errorf("start browser runtime: %w", err)
	}
	return &chromedpRuntime{
		browserCtx: browserCtx, browserCancel: browserCancel, allocCancel: allocCancel,
	}, nil
}

func (r *chromedpRuntime) capture(ctx context.Context, request runtimeCaptureRequest) (gp.AuthArtifact, error) {
	if err := ctx.Err(); err != nil {
		return gp.AuthArtifact{}, fmt.Errorf("capture auth artifact: %w", err)
	}
	captureCtx, cancel := context.WithTimeout(r.browserCtx, captureTimeout(request.timeout))
	stopCancel := context.AfterFunc(ctx, cancel)
	defer func() {
		stopCancel()
		cancel()
	}()

	events := make(chan responseEvent, 128)
	results := make(chan captureResult, 1)
	chromedp.ListenTarget(captureCtx, listenForResponses(events, results))
	go collectArtifacts(captureCtx, captureCtx, events, results, readResponseBody)
	if err := chromedp.Run(captureCtx, network.Enable(), chromedp.Navigate(request.target)); err != nil {
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

func (r *chromedpRuntime) close() error {
	err := chromedp.Cancel(r.browserCtx)
	r.browserCancel()
	r.allocCancel()
	return err
}

type runnerRuntime struct {
	runner browserRunner
	config browserRuntimeConfig
}

func runnerRuntimeFactory(runner browserRunner) browserRuntimeFactory {
	return func(_ context.Context, config browserRuntimeConfig) (browserRuntime, error) {
		if runner == nil {
			return nil, fmt.Errorf("start browser runtime: missing runner")
		}
		return &runnerRuntime{runner: runner, config: config}, nil
	}
}

func (r *runnerRuntime) capture(ctx context.Context, request runtimeCaptureRequest) (gp.AuthArtifact, error) {
	return r.runner(ctx, browserRunRequest{
		browserPath: r.config.browserPath,
		profileDir:  r.config.profileDir,
		target:      request.target,
		timeout:     request.timeout,
	})
}

func (*runnerRuntime) close() error { return nil }
