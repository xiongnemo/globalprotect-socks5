package gp

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
)

type GatewaySession struct {
	AuthCookie  Secret
	Portal      string
	User        string
	Domain      string
	Computer    string
	PreferredIP string
}

func (c Client) GatewayLogin(ctx context.Context, gateway PortalURL, artifact AuthArtifact) (GatewaySession, error) {
	form := c.gatewayLoginForm(gateway, artifact)
	body, err := c.postForm(ctx, postFormRequest{stage: "gateway_login", endpoint: gateway.endpoint("/ssl-vpn/login.esp"), form: form})
	if err != nil {
		return GatewaySession{}, err
	}
	session, err := parseGatewaySession(body)
	if err != nil {
		return GatewaySession{}, err
	}
	session.Computer = c.profile.Computer
	return session, nil
}

func (c Client) GatewayPrelogin(ctx context.Context, gateway PortalURL) (Prelogin, error) {
	body, err := c.postForm(ctx, postFormRequest{stage: "gateway_prelogin", endpoint: gateway.endpoint("/ssl-vpn/prelogin.esp"), form: c.preloginForm(), label: "gateway prelogin"})
	if err != nil {
		return Prelogin{}, err
	}
	prelogin, err := ParsePrelogin(body)
	if err != nil {
		return Prelogin{}, err
	}
	return prelogin, nil
}

func (c Client) gatewayLoginForm(gateway PortalURL, artifact AuthArtifact) url.Values {
	form := url.Values{}
	form.Set("jnlpReady", "jnlpReady")
	form.Set("ok", "Login")
	form.Set("direct", "yes")
	form.Set("clientVer", "4100")
	form.Set("prot", "https:")
	form.Set("ipv6-support", "no")
	form.Set("clientos", string(c.profile.ClientOS))
	form.Set("os-version", strings.ToLower(string(c.profile.ClientOS)))
	form.Set("clientgpversion", "4.1.0.98")
	form.Set("server", gateway.Hostname())
	form.Set("host-id", c.profile.HostID)
	form.Set("serialno", c.profile.HostID)
	form.Set("preferred-ip", "")
	form.Set("preferred-ipv6", "")
	form.Set("inputStr", "")
	form.Set("computer", c.profile.Computer)
	setAuthArtifactFields(form, artifact)
	if artifact.PortalUserAuthCookie.String() != "" || artifact.PortalPrelogonUserAuthCookie.String() != "" {
		form.Set("host", gateway.Hostname())
		form.Set("gw", gateway.Hostname())
		form.Set("gateway-name", gateway.Hostname())
		form.Set("internal", "no")
		form.Set("selection-type", "auto")
		form.Set("connect-method", "user-logon")
		form.Set("client-ip", "")
		form.Set("client-ipv6", "")
	}
	return form
}

type jnlpLogin struct {
	Arguments []string `xml:"application-desc>argument"`
}

func parseGatewaySession(body []byte) (GatewaySession, error) {
	var parsed jnlpLogin
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return GatewaySession{}, fmt.Errorf("decode gateway login xml: %w", err)
	}
	if len(parsed.Arguments) < 15 {
		return GatewaySession{}, fmt.Errorf("gateway login arguments: %w", ErrMissingAuthArtifact)
	}
	authCookie, err := NewSecret(optionalValueAt(parsed.Arguments, 1))
	if err != nil {
		return GatewaySession{}, fmt.Errorf("gateway login auth cookie: %w", ErrMissingAuthArtifact)
	}
	user := optionalValueAt(parsed.Arguments, 4)
	if user == "" {
		return GatewaySession{}, fmt.Errorf("gateway login user: %w", ErrMissingAuthArtifact)
	}
	if optionalValueAt(parsed.Arguments, 12) != "tunnel" {
		return GatewaySession{}, fmt.Errorf("gateway login connection type: %w", ErrInvalidAuthArtifact)
	}
	if optionalValueAt(parsed.Arguments, 14) != "4100" {
		return GatewaySession{}, fmt.Errorf("gateway login client version: %w", ErrInvalidAuthArtifact)
	}
	return GatewaySession{
		AuthCookie:  authCookie,
		Portal:      optionalValueAt(parsed.Arguments, 3),
		User:        user,
		Domain:      optionalValueAt(parsed.Arguments, 7),
		PreferredIP: optionalValueAt(parsed.Arguments, 15),
	}, nil
}

func optionalValueAt(values []string, index int) string {
	if index >= len(values) {
		return ""
	}
	value := values[index]
	if value == "(null)" || value == "-1" {
		return ""
	}
	return value
}
