package app

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func (r Runner) probe(ctx context.Context, config probeConfig) (err error) {
	debugLog, clientOptions, err := openDebugLog(config.debugLogPath)
	if err != nil {
		return err
	}
	defer closeDebugLog(debugLog, config.debugLogPath, &err)
	portal, err := gp.NewPortalURL(config.portalRaw)
	if err != nil {
		return fmt.Errorf("portal: %w", err)
	}
	client := gp.NewClient(r.io.HTTPClient, gp.ClientProfile{HostID: config.hostID, Computer: "gp-socks", ClientOS: gp.ClientOSLinux}, clientOptions...)
	prelogin, err := client.Prelogin(ctx, portal)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.io.Stdout, "auth=%s method=%s default_browser=%t region=%s\n", prelogin.AuthMode, prelogin.SAMLMethod, prelogin.DefaultBrowser, prelogin.Region)
	if err != nil {
		return fmt.Errorf("write probe summary: %w", err)
	}
	if prelogin.SAMLRequest.String() != "" && prelogin.SAMLMethod == gp.SAMLPost && config.ssoFile != "" {
		if err := os.WriteFile(config.ssoFile, []byte(prelogin.SAMLRequest.String()), 0o600); err != nil {
			return fmt.Errorf("write sso file: %w", err)
		}
		_, err = fmt.Fprintf(r.io.Stdout, "sso_file=%s\n", config.ssoFile)
		if err != nil {
			return fmt.Errorf("write sso file path: %w", err)
		}
		return nil
	}
	if prelogin.SAMLRequest.String() != "" {
		_, err = fmt.Fprintf(r.io.Stdout, "sso_url=%s\n", summarizeSSORequest(prelogin.SAMLRequest.String()))
		if err != nil {
			return fmt.Errorf("write sso url: %w", err)
		}
	}
	return nil
}

func summarizeSSORequest(raw string) string {
	if strings.HasPrefix(strings.TrimSpace(raw), "<") {
		return "<SAML POST HTML; rerun with --sso-file to save>"
	}
	return raw
}
