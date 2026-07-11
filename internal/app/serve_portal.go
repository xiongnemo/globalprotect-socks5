package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

type portalLoginRequest struct {
	client     gp.Client
	portal     gp.PortalURL
	gatewayRaw string
	artifact   gp.AuthArtifact
}

type portalLoginMaterial struct {
	gateway  gp.PortalURL
	artifact gp.AuthArtifact
}

func resolvePortalLogin(ctx context.Context, request portalLoginRequest) (portalLoginMaterial, error) {
	config, err := request.client.PortalConfig(ctx, request.portal, request.artifact)
	if err != nil {
		return portalLoginMaterial{}, fmt.Errorf("portal config: %w", err)
	}
	gateway, err := resolveGateway(request.portal, request.gatewayRaw, config)
	if err != nil {
		return portalLoginMaterial{}, err
	}
	return portalLoginMaterial{gateway: gateway, artifact: portalGatewayArtifact(request.artifact, config)}, nil
}

func resolveGateway(portal gp.PortalURL, gatewayRaw string, config gp.PortalConfig) (gp.PortalURL, error) {
	if strings.TrimSpace(gatewayRaw) != "" {
		gateway, err := gp.NewPortalURL(gatewayRaw)
		if err != nil {
			return gp.PortalURL{}, fmt.Errorf("gateway: %w", err)
		}
		return gateway, nil
	}
	for _, gateway := range config.ExternalGateways {
		parsed, err := gatewayURL(portal, gateway.Name)
		if err == nil {
			return parsed, nil
		}
	}
	return gp.PortalURL{}, fmt.Errorf("portal external gateway: %w", gp.ErrInvalidPortalURL)
}

func gatewayURL(portal gp.PortalURL, raw string) (gp.PortalURL, error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.Contains(trimmed, "://") {
		trimmed = portal.Scheme() + "://" + trimmed
	}
	return gp.NewPortalURL(trimmed)
}

func portalGatewayArtifact(artifact gp.AuthArtifact, config gp.PortalConfig) gp.AuthArtifact {
	return gp.AuthArtifact{Kind: artifact.Kind, Username: artifact.Username, PortalUserAuthCookie: config.PortalUserAuthCookie}
}
