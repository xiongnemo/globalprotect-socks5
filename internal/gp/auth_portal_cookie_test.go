package gp_test

import (
	"errors"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_ParseAuthResponse_returnsPortalPrelogonCookie(t *testing.T) {
	tests := []struct {
		name  string
		parse func() (gp.AuthArtifact, error)
	}{
		{
			name: "query",
			parse: func() (gp.AuthArtifact, error) {
				return gp.ParseAuthArtifact("saml-username=alice&portal-prelogonuserauthcookie=prelogon-cookie")
			},
		},
		{
			name: "header",
			parse: func() (gp.AuthArtifact, error) {
				return gp.ParseAuthHeaders(map[string]string{
					"Saml-Username":                   "alice",
					"Portal-PrelogonUserAuthCookie":   "prelogon-cookie",
					"Header-That-Must-Remain-Ignored": "secret-ignored-value",
				})
			},
		},
		{
			name: "html",
			parse: func() (gp.AuthArtifact, error) {
				return gp.ParseAuthBody(`<saml-username>alice</saml-username>` +
					`<portal-prelogonuserauthcookie>prelogon-cookie</portal-prelogonuserauthcookie>`)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact, err := test.parse()
			if err != nil {
				t.Fatalf("parse auth response: %v", err)
			}
			if artifact.PortalPrelogonUserAuthCookie.String() != "prelogon-cookie" {
				t.Fatalf("PortalPrelogonUserAuthCookie = %q, want prelogon-cookie",
					artifact.PortalPrelogonUserAuthCookie.String())
			}
		})
	}
}

func Test_ParseAuthArtifact_rejectsEmptyPortalCookieSentinel(t *testing.T) {
	_, err := gp.ParseAuthArtifact("saml-username=alice&portal-prelogonuserauthcookie=empty")
	if !errors.Is(err, gp.ErrMissingAuthArtifact) {
		t.Fatalf("error = %v, want ErrMissingAuthArtifact", err)
	}
}
