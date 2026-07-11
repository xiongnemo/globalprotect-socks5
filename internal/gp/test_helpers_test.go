package gp_test

import (
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func mustPortalURL(t *testing.T, raw string) gp.PortalURL {
	t.Helper()
	portal, err := gp.NewPortalURL(raw)
	if err != nil {
		t.Fatalf("NewPortalURL() error = %v", err)
	}
	return portal
}
