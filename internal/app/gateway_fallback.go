package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

type gatewayLoginRequest struct {
	client   gp.Client
	gateway  gp.PortalURL
	artifact gp.AuthArtifact
	options  serveTunnelOptions
	capturer AuthCapturer
}

func (r Runner) gatewayLoginWithFallback(ctx context.Context, request gatewayLoginRequest, logger *appLogger) (gp.GatewaySession, error) {
	prelogin, err := request.client.GatewayPrelogin(ctx, request.gateway)
	if err != nil {
		return gp.GatewaySession{}, fmt.Errorf("gateway prelogin: %w", err)
	}
	if hasPortalCredential(request.artifact) {
		session, loginErr := request.client.GatewayLogin(ctx, request.gateway, request.artifact)
		if loginErr == nil {
			return session, nil
		}
		if !errors.Is(loginErr, gp.ErrGatewayAuthFailed) {
			return gp.GatewaySession{}, fmt.Errorf("gateway login: %w", loginErr)
		}
		logger.warnGatewayFallback()
	}
	if prelogin.AuthMode != gp.AuthModeSAML || prelogin.SAMLRequest.String() == "" {
		return gp.GatewaySession{}, fmt.Errorf("gateway prelogin requires SAML: %w", gp.ErrInvalidPrelogin)
	}
	capturer := request.capturer
	if capturer == nil {
		capturer = r.authCapturer()
	}
	artifact, err := capturer.Capture(ctx, browserauth.Request{
		Prelogin:    prelogin,
		Browser:     request.options.browser,
		BrowserPath: request.options.browserPath,
		ProfileDir:  request.options.profileDir,
		Timeout:     request.options.timeout,
	})
	if err != nil {
		return gp.GatewaySession{}, fmt.Errorf("capture gateway browser auth: %w", err)
	}
	session, err := request.client.GatewayLogin(ctx, request.gateway, gp.AuthArtifact{
		Kind:           artifact.Kind,
		Username:       artifact.Username,
		PreloginCookie: artifact.PreloginCookie,
	})
	if err != nil {
		return gp.GatewaySession{}, fmt.Errorf("gateway login retry: %w", err)
	}
	return session, nil
}

func hasPortalCredential(artifact gp.AuthArtifact) bool {
	return artifact.PortalUserAuthCookie.String() != "" || artifact.PortalPrelogonUserAuthCookie.String() != ""
}
