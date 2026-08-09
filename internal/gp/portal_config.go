package gp

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
)

type PortalConfig struct {
	PortalUserAuthCookie         Secret
	PortalPrelogonUserAuthCookie Secret
	ExternalGateways             []ExternalGateway
}

type ExternalGateway struct {
	Name        string
	Description string
}

type portalConfigXML struct {
	PortalUserAuthCookie         string             `xml:"portal-userauthcookie"`
	PortalPrelogonUserAuthCookie string             `xml:"portal-prelogonuserauthcookie"`
	ExternalGateways             []portalGatewayXML `xml:"gateways>external>list>entry"`
	Policy                       portalPolicyXML    `xml:"policy"`
}

type portalPolicyXML struct {
	PortalUserAuthCookie         string             `xml:"portal-userauthcookie"`
	PortalPrelogonUserAuthCookie string             `xml:"portal-prelogonuserauthcookie"`
	ExternalGateways             []portalGatewayXML `xml:"gateways>external>list>entry"`
}

type portalGatewayXML struct {
	Name        string `xml:"name,attr"`
	Description string `xml:"description"`
}

func (c Client) PortalConfig(ctx context.Context, portal PortalURL, artifact AuthArtifact) (PortalConfig, error) {
	form := c.portalConfigForm(portal, artifact)
	body, err := c.postForm(ctx, postFormRequest{stage: "portal_config", endpoint: portal.endpoint("/global-protect/getconfig.esp"), form: form, label: "portal config"})
	if err != nil {
		return PortalConfig{}, err
	}
	config, err := ParsePortalConfig(body)
	if err != nil {
		return PortalConfig{}, err
	}
	return config, nil
}

func (c Client) portalConfigForm(portal PortalURL, artifact AuthArtifact) url.Values {
	form := url.Values{}
	form.Set("jnlpReady", "jnlpReady")
	form.Set("ok", "Login")
	form.Set("direct", "yes")
	form.Set("clientVer", "4100")
	form.Set("prot", "https:")
	form.Set("inputStr", "")
	setAuthArtifactFields(form, artifact)
	form.Set("clientgpversion", "4.1.0.98")
	form.Set("ipv6-support", "no")
	form.Set("clientos", string(c.profile.ClientOS))
	form.Set("os-version", strings.ToLower(string(c.profile.ClientOS)))
	form.Set("server", portal.Hostname())
	form.Set("host", portal.Hostname())
	form.Set("host-id", c.profile.HostID)
	form.Set("serialno", c.profile.HostID)
	form.Set("csc-digest", "")
	form.Set("config-digest", "")
	form.Set("csc-support", "no")
	form.Set("swg-auth-token", "0")
	form.Set("swg-nonce", "0")
	form.Set("computer", c.profile.Computer)
	return form
}

func setAuthArtifactFields(form url.Values, artifact AuthArtifact) {
	form.Set("user", artifact.Username)
	form.Set("passwd", "")
	form.Set("prelogin-cookie", artifact.PreloginCookie.String())
	form.Set("token", artifact.Token.String())
	form.Set("portal-userauthcookie", portalAuthCookieValue(artifact.PortalUserAuthCookie))
	form.Set("portal-prelogonuserauthcookie", portalAuthCookieValue(artifact.PortalPrelogonUserAuthCookie))
}

func portalAuthCookieValue(cookie Secret) string {
	if cookie.String() == "" {
		return "empty"
	}
	return cookie.String()
}

func ParsePortalConfig(body []byte) (PortalConfig, error) {
	var parsed portalConfigXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return PortalConfig{}, fmt.Errorf("decode portal config xml: %w", err)
	}
	policy := parsed.policy()
	portalCookie, err := optionalSecret(policy.PortalUserAuthCookie)
	if err != nil {
		return PortalConfig{}, fmt.Errorf("portal user auth cookie: %w", err)
	}
	prelogonCookie, err := optionalSecret(policy.PortalPrelogonUserAuthCookie)
	if err != nil {
		return PortalConfig{}, fmt.Errorf("portal prelogon user auth cookie: %w", err)
	}
	return PortalConfig{
		PortalUserAuthCookie:         portalCookie,
		PortalPrelogonUserAuthCookie: prelogonCookie,
		ExternalGateways:             portalGateways(policy.ExternalGateways),
	}, nil
}

func (p portalConfigXML) policy() portalPolicyXML {
	policy := p.Policy
	if strings.TrimSpace(p.PortalUserAuthCookie) != "" {
		policy.PortalUserAuthCookie = p.PortalUserAuthCookie
	}
	if strings.TrimSpace(p.PortalPrelogonUserAuthCookie) != "" {
		policy.PortalPrelogonUserAuthCookie = p.PortalPrelogonUserAuthCookie
	}
	if len(p.ExternalGateways) > 0 {
		policy.ExternalGateways = p.ExternalGateways
	}
	return policy
}

func portalGateways(entries []portalGatewayXML) []ExternalGateway {
	gateways := make([]ExternalGateway, 0, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			continue
		}
		gateways = append(gateways, ExternalGateway{Name: name, Description: strings.TrimSpace(entry.Description)})
	}
	return gateways
}
