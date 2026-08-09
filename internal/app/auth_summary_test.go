package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func TestRunner_writeAuthSummaryReportsPrelogonOnlyPortalCookie(t *testing.T) {
	cookie, err := gp.NewSecret("prelogon-secret")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	var output bytes.Buffer
	runner := NewRunner(IO{Stdout: &output})

	err = runner.writeAuthSummary(gp.AuthArtifact{
		Kind: gp.ArtifactSAML, Username: "alice@example.test", PortalPrelogonUserAuthCookie: cookie,
	})

	if err != nil {
		t.Fatalf("writeAuthSummary() error = %v", err)
	}
	if !strings.Contains(output.String(), "portal_cookie_present=true") {
		t.Fatalf("summary = %q, want portal cookie presence", output.String())
	}
	if strings.Contains(output.String(), cookie.String()) {
		t.Fatalf("summary leaked portal prelogon cookie: %q", output.String())
	}
}
