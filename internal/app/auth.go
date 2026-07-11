package app

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

const defaultBrowserAuthTimeout = 5 * time.Minute

type AuthCapturer interface {
	Capture(context.Context, browserauth.Request) (gp.AuthArtifact, error)
}

func (r Runner) auth(ctx context.Context, args []string) (err error) {
	flags := flag.NewFlagSet("auth", flag.ContinueOnError)
	flags.SetOutput(r.io.Stderr)
	portalRaw := flags.String("portal", "", "GlobalProtect portal URL")
	hostID := flags.String("host-id", "gp-socks", "stable GlobalProtect host-id")
	browserRaw := flags.String("browser", string(browserauth.BrowserAuto), "browser: auto, chrome, or edge")
	browserPath := flags.String("browser-path", "", "explicit Chrome or Edge executable path")
	browserProfileDir := flags.String("browser-profile-dir", "", "explicit persistent Chrome/Edge profile directory for browser SSO")
	timeout := flags.Duration("timeout", defaultBrowserAuthTimeout, "maximum time to wait for browser SSO")
	debugLogPath := flags.String("debug-log", "", "write redacted GlobalProtect HTTP debug JSONL to this file")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse auth flags: %w", err)
	}
	debugLog, clientOptions, err := openDebugLog(*debugLogPath)
	if err != nil {
		return err
	}
	defer closeDebugLog(debugLog, *debugLogPath, &err)
	browser, err := browserauth.ParseBrowser(*browserRaw)
	if err != nil {
		return err
	}
	portal, err := gp.NewPortalURL(*portalRaw)
	if err != nil {
		return fmt.Errorf("portal: %w", err)
	}
	client := gp.NewClient(r.io.HTTPClient, gp.ClientProfile{HostID: *hostID, Computer: "gp-socks", ClientOS: gp.ClientOSLinux}, clientOptions...)
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
		BrowserPath: *browserPath,
		ProfileDir:  *browserProfileDir,
		Timeout:     *timeout,
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
	_, err := fmt.Fprintf(r.io.Stdout, "kind=%s username=%s token_present=%t prelogin_cookie_present=%t portal_cookie_present=%t\n",
		artifact.Kind,
		artifact.Username,
		artifact.Token.String() != "",
		artifact.PreloginCookie.String() != "",
		artifact.PortalUserAuthCookie.String() != "",
	)
	if err != nil {
		return fmt.Errorf("write auth summary: %w", err)
	}
	return nil
}
