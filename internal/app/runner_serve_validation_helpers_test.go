package app_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

var errUnexpectedServeSideEffect = errors.New("unexpected serve side effect")

type countingAuthCapturer struct {
	calls int
}

func (capturer *countingAuthCapturer) Capture(context.Context, browserauth.Request) (gp.AuthArtifact, error) {
	capturer.calls++
	return gp.AuthArtifact{}, errUnexpectedServeSideEffect
}

type countingPacketTunnelConnector struct {
	calls int
}

func (connector *countingPacketTunnelConnector) ConnectPacketTunnel(context.Context, app.PacketTunnelRequest) (tunnel.PacketTunnel, error) {
	connector.calls++
	return nil, errUnexpectedServeSideEffect
}

type serveSideEffects struct {
	stdout         bytes.Buffer
	applicationLog bytes.Buffer
	httpCalls      int
	dialCalls      int
	authCapturer   countingAuthCapturer
	connector      countingPacketTunnelConnector
}

func (effects *serveSideEffects) runner(lookupEnv func(string) (string, bool)) app.Runner {
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		effects.httpCalls++
		return nil, errUnexpectedServeSideEffect
	})}
	return app.NewRunner(app.IO{
		Stdout:                &effects.stdout,
		Stderr:                io.Discard,
		LogWriter:             &effects.applicationLog,
		LookupEnv:             lookupEnv,
		HTTPClient:            httpClient,
		AuthCapturer:          &effects.authCapturer,
		DialContext:           effects.dialContext,
		PacketTunnelConnector: &effects.connector,
	})
}

func (effects *serveSideEffects) dialContext(context.Context, string, string) (net.Conn, error) {
	effects.dialCalls++
	return nil, errUnexpectedServeSideEffect
}

func (effects *serveSideEffects) assertCollaboratorsIdle(t *testing.T) {
	t.Helper()
	if effects.httpCalls != 0 {
		t.Errorf("HTTP calls = %d, want 0", effects.httpCalls)
	}
	if effects.authCapturer.calls != 0 {
		t.Errorf("auth capture calls = %d, want 0", effects.authCapturer.calls)
	}
	if effects.connector.calls != 0 {
		t.Errorf("packet tunnel calls = %d, want 0", effects.connector.calls)
	}
	if effects.dialCalls != 0 {
		t.Errorf("direct dial calls = %d, want 0", effects.dialCalls)
	}
	if effects.stdout.Len() != 0 {
		t.Errorf("stdout = %q, want no listener output", effects.stdout.String())
	}
}
