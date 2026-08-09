package app

import (
	"context"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func TestNewServeCaptureSessionUsesLiveSessionForDefaultCapturer(t *testing.T) {
	capturer, session := newServeCaptureSession(context.Background(), browserauth.NewCapturer())

	if session == nil {
		t.Fatal("capture session = nil, want live browser session")
	}
	t.Cleanup(func() { _ = session.Close() })
	if capturer != session {
		t.Fatalf("capturer = %T, want returned capture session", capturer)
	}
}

func TestNewServeCaptureSessionPreservesInjectedCapturer(t *testing.T) {
	fake := staticAuthCapturer{}
	capturer, session := newServeCaptureSession(context.Background(), fake)

	if session != nil {
		t.Fatalf("capture session = %T, want nil for injected capturer", session)
	}
	if _, ok := capturer.(staticAuthCapturer); !ok {
		t.Fatalf("capturer = %T, want injected capturer", capturer)
	}
}

type staticAuthCapturer struct{}

func (staticAuthCapturer) Capture(context.Context, browserauth.Request) (gp.AuthArtifact, error) {
	return gp.AuthArtifact{}, nil
}
