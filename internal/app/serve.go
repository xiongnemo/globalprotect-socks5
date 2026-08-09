package app

import (
	"context"
	"crypto/tls"
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

type PacketTunnelRequest struct {
	Gateway gp.PortalURL
	Session gp.GatewaySession
	Config  gp.TunnelConfig
}

type PacketTunnelConnector interface {
	ConnectPacketTunnel(context.Context, PacketTunnelRequest) (tunnel.PacketTunnel, error)
}

type defaultPacketTunnelConnector struct{}

type serveTunnelOptions struct {
	portalRaw   string
	gatewayRaw  string
	hostID      string
	browser     browserauth.Browser
	browserPath string
	profileDir  string
	clientOpts  []gp.ClientOption
	timeout     time.Duration
}

type serveAuthRequest struct {
	client  gp.Client
	portal  gp.PortalURL
	options serveTunnelOptions
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
	if strings.TrimSpace(config.portalRaw) != "" {
		tunnelDialer, err := r.newTunnelDialer(ctx, serveTunnelOptions{
			portalRaw:   config.portalRaw,
			gatewayRaw:  config.gatewayRaw,
			hostID:      config.hostID,
			browser:     browser,
			browserPath: config.browserPath,
			profileDir:  config.browserProfileDir,
			clientOpts:  clientOptions,
			timeout:     config.timeout,
		}, logger)
		if err != nil {
			return err
		}
		defer tunnelDialer.Close()
		dial = tunnelDialer.DialContext
	}
	listener, err := net.Listen("tcp", config.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", config.listenAddr, withFailureMetadata(err, failureMetadata{
			stage: failureStageListener,
			code:  failureCodeListenFailed,
		}))
	}
	defer listener.Close()
	_, err = fmt.Fprintf(r.io.Stdout, "listening=%s\n", listener.Addr().String())
	if err != nil {
		return fmt.Errorf("write listen summary: %w", err)
	}
	server := socks5.NewServer(socks5.Config{DialContext: dial})
	return server.Serve(ctx, listener)
}

func (r Runner) newTunnelDialer(ctx context.Context, options serveTunnelOptions, logger *appLogger) (*tunnel.Dialer, error) {
	portal, err := gp.NewPortalURL(options.portalRaw)
	if err != nil {
		return nil, fmt.Errorf("portal: %w", err)
	}
	client := gp.NewClient(r.io.HTTPClient, gp.ClientProfile{HostID: options.hostID, Computer: "gp-socks", ClientOS: gp.ClientOSLinux}, options.clientOpts...)
	artifact, err := r.captureServeArtifact(ctx, serveAuthRequest{client: client, portal: portal, options: options})
	if err != nil {
		return nil, err
	}
	material, err := resolvePortalLogin(ctx, portalLoginRequest{client: client, portal: portal, gatewayRaw: options.gatewayRaw, artifact: artifact})
	if err != nil {
		return nil, err
	}
	session, err := r.gatewayLoginWithFallback(ctx, gatewayLoginRequest{client: client, gateway: material.gateway, artifact: material.artifact, options: options}, logger)
	if err != nil {
		return nil, err
	}
	config, err := client.GatewayConfig(ctx, material.gateway, session)
	if err != nil {
		return nil, fmt.Errorf("gateway config: %w", err)
	}
	localAddr, err := tunnelLocalAddr(config, session)
	if err != nil {
		return nil, err
	}
	packetTunnel, err := r.packetTunnelConnector().ConnectPacketTunnel(ctx, PacketTunnelRequest{Gateway: material.gateway, Session: session, Config: config})
	if err != nil {
		return nil, fmt.Errorf("connect packet tunnel: %w", err)
	}
	dialer, err := tunnel.NewDialer(ctx, tunnel.Config{Tunnel: packetTunnel, LocalAddr: localAddr})
	if err != nil {
		_ = packetTunnel.Close()
		return nil, fmt.Errorf("create tunnel dialer: %w", err)
	}
	return dialer, nil
}

func (r Runner) captureServeArtifact(ctx context.Context, request serveAuthRequest) (gp.AuthArtifact, error) {
	prelogin, err := request.client.Prelogin(ctx, request.portal)
	if err != nil {
		return gp.AuthArtifact{}, err
	}
	if prelogin.AuthMode != gp.AuthModeSAML || prelogin.SAMLRequest.String() == "" {
		return gp.AuthArtifact{}, fmt.Errorf("serve prelogin requires SAML: %w", gp.ErrInvalidPrelogin)
	}
	artifact, err := r.authCapturer().Capture(ctx, browserauth.Request{
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

func (r Runner) packetTunnelConnector() PacketTunnelConnector {
	if r.io.PacketTunnelConnector != nil {
		return r.io.PacketTunnelConnector
	}
	return defaultPacketTunnelConnector{}
}

func (defaultPacketTunnelConnector) ConnectPacketTunnel(ctx context.Context, request PacketTunnelRequest) (tunnel.PacketTunnel, error) {
	conn, err := dialGateway(ctx, request.Gateway)
	if err != nil {
		return nil, err
	}
	packetTunnel, err := gp.NewSSLPacketTunnel(ctx, conn, request.Session, request.Config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return packetTunnel, nil
}

func dialGateway(ctx context.Context, gateway gp.PortalURL) (net.Conn, error) {
	if gateway.Scheme() == "http" {
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", gateway.TCPAddress())
		if err != nil {
			return nil, fmt.Errorf("dial gateway %s: %w", gateway.TCPAddress(), err)
		}
		return conn, nil
	}
	dialer := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: gateway.Hostname()}}
	conn, err := dialer.DialContext(ctx, "tcp", gateway.TCPAddress())
	if err != nil {
		return nil, fmt.Errorf("dial gateway %s: %w", gateway.TCPAddress(), err)
	}
	return conn, nil
}

func dialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}
