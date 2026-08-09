package browserauth

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	runtime, err := newChromedpRuntime(ctx, browserRuntimeConfig{
		browserPath: request.browserPath,
		profileDir:  request.profileDir,
	})
	if err != nil {
		return gp.AuthArtifact{}, err
	}
	artifact, captureErr := runtime.capture(ctx, runtimeCaptureRequest{
		target: request.target, timeout: request.timeout,
	})
	closeErr := runtime.close()
	if closeErr != nil {
		closeErr = fmt.Errorf("close browser runtime: %w", closeErr)
	}
	return artifact, errors.Join(captureErr, closeErr)
}

func captureTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return defaultCaptureTimeout
}
