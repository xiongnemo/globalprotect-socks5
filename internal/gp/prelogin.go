package gp

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
)

type preloginXML struct {
	SAMLMethod     string `xml:"saml-auth-method"`
	SAMLRequest    string `xml:"saml-request"`
	DefaultBrowser string `xml:"saml-default-browser"`
	Region         string `xml:"region"`
	AuthMethod     string `xml:"auth-method"`
}

func ParsePrelogin(body []byte) (Prelogin, error) {
	var parsed preloginXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return Prelogin{}, fmt.Errorf("decode prelogin xml: %w", err)
	}
	if parsed.SAMLRequest == "" {
		return Prelogin{AuthMode: AuthModePassword}, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(parsed.SAMLRequest)
	if err != nil {
		return Prelogin{}, fmt.Errorf("decode saml request: %w", err)
	}
	request, err := NewSAMLRequest(string(decoded))
	if err != nil {
		return Prelogin{}, err
	}
	return Prelogin{
		AuthMode:       AuthModeSAML,
		SAMLMethod:     SAMLMethod(parsed.SAMLMethod),
		SAMLRequest:    request,
		DefaultBrowser: isTrue(parsed.DefaultBrowser),
		Region:         parsed.Region,
	}, nil
}

func isTrue(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y":
		return true
	default:
		return false
	}
}
