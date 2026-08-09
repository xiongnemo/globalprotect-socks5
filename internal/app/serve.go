package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/browserauth"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

type serveTunnelOptions struct {
	portalRaw   string
	gatewayRaw  string
	hostID      string
	browser     browserauth.Browser
	browserPath string
	profileDir  string
	clientOpts  []gp.ClientOption
	timeout     time.Duration
	dnsMode     serveDNSMode
	dnsServers  []netip.Addr
}

type serveAuthRequest struct {
	client   gp.Client
	portal   gp.PortalURL
	options  serveTunnelOptions
	capturer AuthCapturer
}

func (r Runner) serve(ctx context.Context, config serveConfig, logger *appLogger) (err error) {
	debugLog, clientOptions, err := openDebugLog(config.debugLogPath)
	if err != nil {
		return err
	}
	defer closeDebugLog(debugLog, config.debugLogPath, &err)
	browser, err := browserauth.ParseBrowser(config.browserRaw)
	if err != nil {
		return err
	}
	dial := r.io.DialContext
	var supervisor *tunnelSupervisor
	if strings.TrimSpace(config.portalRaw) != "" {
		supervisor, err = r.newTunnelDialer(ctx, serveTunnelOptions{
			portalRaw:   config.portalRaw,
			gatewayRaw:  config.gatewayRaw,
			hostID:      config.hostID,
			browser:     browser,
			browserPath: config.browserPath,
			profileDir:  config.browserProfileDir,
			clientOpts:  clientOptions,
			timeout:     config.timeout,
			dnsMode:     config.dnsMode,
			dnsServers:  config.dnsServers,
		}, logger)
		if err != nil {
			return err
		}
		defer supervisor.Close()
		dial = supervisor.DialContext
	}
	listener, err := net.Listen("tcp", config.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", config.listenAddr, withFailureMetadata(err, failureMetadata{
			stage: failureStageListener,
			code:  failureCodeListenFailed,
		}))
	}
	defer listener.Close()
	if err := validateBoundListenAddress(listener.Addr(), config.allowNonLoopback, config.socksCredentials); err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.io.Stdout, "listening=%s\n", listener.Addr().String())
	if err != nil {
		return fmt.Errorf("write listen summary: %w", err)
	}
	server := socks5.NewServer(socks5.Config{
		DialContext: dial, Credentials: config.socksCredentials,
		HandshakeTimeout: config.handshakeTimeout, ConnectTimeout: config.connectTimeout,
		MaxConnections: config.maxConnections,
	})
	if supervisor == nil {
		return server.Serve(ctx, listener)
	}
	return serveWithTunnelHealth(ctx, server, listener, supervisor)
}

func (r Runner) captureServeArtifact(ctx context.Context, request serveAuthRequest) (gp.AuthArtifact, error) {
	prelogin, err := request.client.Prelogin(ctx, request.portal)
	if err != nil {
		return gp.AuthArtifact{}, err
	}
	if prelogin.AuthMode != gp.AuthModeSAML || prelogin.SAMLRequest.String() == "" {
		return gp.AuthArtifact{}, fmt.Errorf("serve prelogin requires SAML: %w", gp.ErrInvalidPrelogin)
	}
	capturer := request.capturer
	if capturer == nil {
		capturer = r.authCapturer()
	}
	artifact, err := capturer.Capture(ctx, browserauth.Request{
		Prelogin:    prelogin,
		Browser:     request.options.browser,
		BrowserPath: request.options.browserPath,
		ProfileDir:  request.options.profileDir,
		Timeout:     request.options.timeout,
	})
	if err != nil {
		return gp.AuthArtifact{}, fmt.Errorf("capture browser auth: %w", err)
	}
	return artifact, nil
}

func tunnelLocalAddr(config gp.TunnelConfig, session gp.GatewaySession) (netip.Addr, error) {
	if config.IP.IsValid() {
		if !config.IP.Is4() {
			return netip.Addr{}, fmt.Errorf("gateway config ip %s: %w", config.IP, tunnel.ErrIPv6Unsupported)
		}
		return config.IP, nil
	}
	if strings.TrimSpace(session.PreferredIP) == "" {
		return netip.Addr{}, fmt.Errorf("gateway config ip: %w", tunnel.ErrInvalidConfig)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(session.PreferredIP))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("gateway preferred ip: %w", err)
	}
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("gateway preferred ip %s: %w", addr, tunnel.ErrIPv6Unsupported)
	}
	return addr, nil
}

func dialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}
