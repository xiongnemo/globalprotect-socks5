package gp

import (
	"context"
	"net/netip"
	"net/url"
	"strings"
)

type TunnelConfig struct {
	IP            netip.Addr
	SSLTunnelURL  string
	DNS           []netip.Addr
	IncludeRoutes []netip.Prefix
	ExcludeRoutes []netip.Prefix
}

func (c Client) GatewayConfig(ctx context.Context, gateway PortalURL, session GatewaySession) (TunnelConfig, error) {
	form := c.gatewayConfigForm(session)
	body, err := c.postForm(ctx, postFormRequest{stage: "gateway_config", endpoint: gateway.endpoint("/ssl-vpn/getconfig.esp"), form: form})
	if err != nil {
		return TunnelConfig{}, err
	}
	config, err := parseTunnelConfig(body)
	if err != nil {
		return TunnelConfig{}, err
	}
	return config, nil
}

func (c Client) gatewayConfigForm(session GatewaySession) url.Values {
	form := url.Values{}
	form.Set("client-type", "1")
	form.Set("protocol-version", "p1")
	form.Set("internal", "no")
	form.Set("app-version", "5.1.5-8")
	form.Set("ipv6-support", "no")
	form.Set("clientos", string(c.profile.ClientOS))
	form.Set("os-version", strings.ToLower(string(c.profile.ClientOS)))
	form.Set("hmac-algo", "sha1,md5,sha256")
	form.Set("enc-algo", "aes-128-cbc,aes-256-cbc")
	form.Set("user", session.User)
	form.Set("authcookie", session.AuthCookie.String())
	form.Set("computer", session.Computer)
	form.Set("preferred-ip", session.PreferredIP)
	if session.Portal != "" {
		form.Set("portal", session.Portal)
	}
	if session.Domain != "" {
		form.Set("domain", session.Domain)
	}
	return form
}
