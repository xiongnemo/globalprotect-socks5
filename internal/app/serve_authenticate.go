package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

type authenticatedGateway struct {
	client  gp.Client
	gateway gp.PortalURL
	session gp.GatewaySession
}

type captureSessionFactory interface {
	NewCaptureSession(context.Context) *browserauth.CaptureSession
}

func (r Runner) authenticateGateway(ctx context.Context, options serveTunnelOptions, logger *appLogger) (result authenticatedGateway, err error) {
	portal, err := gp.NewPortalURL(options.portalRaw)
	if err != nil {
		return authenticatedGateway{}, fmt.Errorf("portal: %w", err)
	}
	capturer, captureSession := newServeCaptureSession(ctx, r.authCapturer())
	if captureSession != nil {
		defer closeCaptureSession(captureSession, &err)
	} else {
		profile, profileErr := browserauth.NewProfileSession(options.profileDir)
		if profileErr != nil {
			return authenticatedGateway{}, profileErr
		}
		defer closeProfileSession(profile, &err)
		options.profileDir = profile.ProfileDir()
	}

	client := gp.NewClient(r.io.HTTPClient, gp.ClientProfile{
		HostID: options.hostID, Computer: "gp-socks", ClientOS: gp.ClientOSLinux,
	}, options.clientOpts...)
	artifact, err := r.captureServeArtifact(ctx, serveAuthRequest{
		client: client, portal: portal, options: options, capturer: capturer,
	})
	if err != nil {
		return authenticatedGateway{}, err
	}
	material, err := resolvePortalLogin(ctx, portalLoginRequest{
		client: client, portal: portal, gatewayRaw: options.gatewayRaw, artifact: artifact,
	})
	if err != nil {
		return authenticatedGateway{}, err
	}
	session, err := r.gatewayLoginWithFallback(ctx, gatewayLoginRequest{
		client: client, gateway: material.gateway, artifact: material.artifact, options: options, capturer: capturer,
	}, logger)
	if err != nil {
		return authenticatedGateway{}, err
	}
	return authenticatedGateway{client: client, gateway: material.gateway, session: session}, nil
}

func newServeCaptureSession(ctx context.Context, capturer AuthCapturer) (AuthCapturer, *browserauth.CaptureSession) {
	factory, ok := capturer.(captureSessionFactory)
	if !ok {
		return capturer, nil
	}
	session := factory.NewCaptureSession(ctx)
	return session, session
}

func closeProfileSession(profile *browserauth.ProfileSession, target *error) {
	joinAuthenticationCloseError("close browser profile", profile.Close(), target)
}

func closeCaptureSession(session *browserauth.CaptureSession, target *error) {
	joinAuthenticationCloseError("close browser capture session", session.Close(), target)
}

func joinAuthenticationCloseError(label string, closeErr error, target *error) {
	if closeErr == nil {
		return
	}
	wrapped := fmt.Errorf("%s: %w", label, closeErr)
	if *target == nil {
		*target = wrapped
		return
	}
	*target = errors.Join(*target, wrapped)
}
