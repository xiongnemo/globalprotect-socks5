package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
)

var ErrUsage = errors.New("app: usage")

type IO struct {
	Stdout     io.Writer
	Stderr     io.Writer
	HTTPClient *http.Client
}

type Runner struct {
	io IO
}

func NewRunner(ioConfig IO) Runner {
	if ioConfig.Stdout == nil {
		ioConfig.Stdout = os.Stdout
	}
	if ioConfig.Stderr == nil {
		ioConfig.Stderr = os.Stderr
	}
	if ioConfig.HTTPClient == nil {
		ioConfig.HTTPClient = http.DefaultClient
	}
	return Runner{io: ioConfig}
}

func (r Runner) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return r.usage()
	}
	switch args[0] {
	case "parse-auth":
		return r.parseAuth(args[1:])
	case "probe":
		return r.probe(ctx, args[1:])
	case "serve":
		return r.serve(ctx, args[1:])
	default:
		return r.usage()
	}
}

func (r Runner) parseAuth(args []string) error {
	if len(args) != 1 {
		return r.usage()
	}
	artifact, err := gp.ParseAuthArtifact(args[0])
	if err != nil {
		return fmt.Errorf("parse auth artifact: %w", err)
	}
	_, err = fmt.Fprintf(r.io.Stdout, "kind=%s username=%s token_present=%t prelogin_cookie_present=%t portal_cookie_present=%t\n",
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

func (r Runner) probe(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	flags.SetOutput(r.io.Stderr)
	portalRaw := flags.String("portal", "", "GlobalProtect portal URL")
	hostID := flags.String("host-id", "gp-socks", "stable GlobalProtect host-id")
	ssoFile := flags.String("sso-file", "", "write SAML POST HTML to this file")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse probe flags: %w", err)
	}
	portal, err := gp.NewPortalURL(*portalRaw)
	if err != nil {
		return fmt.Errorf("portal: %w", err)
	}
	client := gp.NewClient(r.io.HTTPClient, gp.ClientProfile{HostID: *hostID, Computer: "gp-socks", ClientOS: gp.ClientOSLinux})
	prelogin, err := client.Prelogin(ctx, portal)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.io.Stdout, "auth=%s method=%s default_browser=%t region=%s\n", prelogin.AuthMode, prelogin.SAMLMethod, prelogin.DefaultBrowser, prelogin.Region)
	if err != nil {
		return fmt.Errorf("write probe summary: %w", err)
	}
	if prelogin.SAMLRequest.String() != "" && prelogin.SAMLMethod == gp.SAMLPost && *ssoFile != "" {
		if err := os.WriteFile(*ssoFile, []byte(prelogin.SAMLRequest.String()), 0o600); err != nil {
			return fmt.Errorf("write sso file: %w", err)
		}
		_, err = fmt.Fprintf(r.io.Stdout, "sso_file=%s\n", *ssoFile)
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

func (r Runner) serve(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(r.io.Stderr)
	listenAddr := flags.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse serve flags: %w", err)
	}
	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listenAddr, err)
	}
	defer listener.Close()
	_, err = fmt.Fprintf(r.io.Stdout, "listening=%s\n", listener.Addr().String())
	if err != nil {
		return fmt.Errorf("write listen summary: %w", err)
	}
	server := socks5.NewServer(socks5.Config{DialContext: dialContext})
	return server.Serve(ctx, listener)
}

func dialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func (r Runner) usage() error {
	_, err := fmt.Fprintln(r.io.Stderr, "usage: gp-socks <parse-auth|probe|serve> [options]")
	if err != nil {
		return fmt.Errorf("write usage: %w", err)
	}
	return ErrUsage
}
