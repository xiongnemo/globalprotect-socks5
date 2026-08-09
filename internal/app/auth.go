package app

import (
	"context"
	"fmt"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

const defaultBrowserAuthTimeout = 5 * time.Minute

type AuthCapturer interface {
	Capture(context.Context, browserauth.Request) (gp.AuthArtifact, error)
}

func (r Runner) auth(ctx context.Context, config authConfig) (err error) {
	debugLog, clientOptions, err := openDebugLog(config.debugLogPath)
	if err != nil {
		return err
	}
	defer closeDebugLog(debugLog, config.debugLogPath, &err)
	browser, err := browserauth.ParseBrowser(config.browserRaw)
	if err != nil {
		return err
	}
	portal, err := gp.NewPortalURL(config.portalRaw)
	if err != nil {
		return fmt.Errorf("portal: %w", err)
	}
	client := gp.NewClient(r.io.HTTPClient, gp.ClientProfile{HostID: config.hostID, Computer: "gp-socks", ClientOS: gp.ClientOSLinux}, clientOptions...)
	prelogin, err := client.Prelogin(ctx, portal)
	if err != nil {
		return err
	}
	if prelogin.AuthMode != gp.AuthModeSAML || prelogin.SAMLRequest.String() == "" {
		return fmt.Errorf("auth prelogin requires SAML: %w", gp.ErrInvalidPrelogin)
	}
	artifact, err := r.authCapturer().Capture(ctx, browserauth.Request{
		Prelogin:    prelogin,
		Browser:     browser,
		BrowserPath: config.browserPath,
		ProfileDir:  config.browserProfileDir,
		Timeout:     config.timeout,
	})
	if err != nil {
		return fmt.Errorf("capture browser auth: %w", err)
	}
	return r.writeAuthSummary(artifact)
}

func (r Runner) authCapturer() AuthCapturer {
	if r.io.AuthCapturer != nil {
		return r.io.AuthCapturer
	}
	capturer := browserauth.NewCapturer()
	return capturer
}

func (r Runner) writeAuthSummary(artifact gp.AuthArtifact) error {
	portalCookiePresent := artifact.PortalUserAuthCookie.String() != "" || artifact.PortalPrelogonUserAuthCookie.String() != ""
	_, err := fmt.Fprintf(r.io.Stdout, "kind=%s username=%s token_present=%t prelogin_cookie_present=%t portal_cookie_present=%t\n",
		artifact.Kind,
		artifact.Username,
		artifact.Token.String() != "",
		artifact.PreloginCookie.String() != "",
		portalCookiePresent,
	)
	if err != nil {
		return fmt.Errorf("write auth summary: %w", err)
	}
	return nil
}
