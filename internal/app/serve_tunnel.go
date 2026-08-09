package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

type PacketTunnelRequest struct {
	Gateway         gp.PortalURL
	Session         gp.GatewaySession
	Config          gp.TunnelConfig
	LifetimeContext context.Context
}

type PacketTunnelConnector interface {
	ConnectPacketTunnel(context.Context, PacketTunnelRequest) (tunnel.PacketTunnel, error)
}

type defaultPacketTunnelConnector struct{}

func (r Runner) newTunnelDialer(ctx context.Context, options serveTunnelOptions, logger *appLogger) (*tunnelSupervisor, error) {
	authenticated, err := r.authenticateGateway(ctx, options, logger)
	if err != nil {
		return nil, err
	}
	config, err := authenticated.client.GatewayConfig(ctx, authenticated.gateway, authenticated.session)
	if err != nil {
		return nil, fmt.Errorf("gateway config: %w", err)
	}
	localAddr, err := tunnelLocalAddr(config, authenticated.session)
	if err != nil {
		return nil, err
	}
	factory := r.tunnelDialerFactory(authenticated, config, localAddr, options)
	lifetimeCtx, cancelLifetime := context.WithCancel(ctx)
	connectCtx, cancelConnect := context.WithTimeout(lifetimeCtx, defaultReconnectTimeout)
	initial, err := factory(connectCtx, lifetimeCtx)
	cancelConnect()
	if err != nil {
		cancelLifetime()
		return nil, err
	}
	return newTunnelSupervisorOnContext(lifetimeCtx, cancelLifetime, initial, factory, supervisorOptions{
		attempts: defaultReconnectAttempts, delay: defaultReconnectDelay, timeout: defaultReconnectTimeout,
	}), nil
}

func (r Runner) tunnelDialerFactory(
	authenticated authenticatedGateway,
	config gp.TunnelConfig,
	localAddr netip.Addr,
	options serveTunnelOptions,
) healthDialerFactory {
	return func(connectCtx, lifetimeCtx context.Context) (healthDialer, error) {
		packetTunnel, err := r.packetTunnelConnector().ConnectPacketTunnel(connectCtx, PacketTunnelRequest{
			Gateway: authenticated.gateway, Session: authenticated.session,
			Config: config, LifetimeContext: lifetimeCtx,
		})
		if err != nil {
			return nil, fmt.Errorf("connect packet tunnel: %w", err)
		}
		resolver, dnsServers := effectiveTunnelDNS(options, config)
		dialer, err := tunnel.NewDialer(lifetimeCtx, tunnel.Config{
			Tunnel: packetTunnel, LocalAddr: localAddr, MTU: config.MTU,
			Resolver: resolver, DNSServers: dnsServers, DNSSearchDomains: config.DNSSuffixes,
		})
		if err != nil {
			_ = packetTunnel.Close()
			return nil, fmt.Errorf("create tunnel dialer: %w", err)
		}
		return dialer, nil
	}
}

func effectiveTunnelDNS(options serveTunnelOptions, config gp.TunnelConfig) (tunnel.Resolver, []netip.Addr) {
	if options.dnsMode == serveDNSModeSystem {
		return net.DefaultResolver, nil
	}
	if len(options.dnsServers) > 0 {
		return nil, append([]netip.Addr(nil), options.dnsServers...)
	}
	servers := make([]netip.Addr, 0, len(config.DNS))
	for _, server := range config.DNS {
		if server.Is4() {
			servers = append(servers, server.Unmap())
		}
	}
	return nil, servers
}

func serveWithTunnelHealth(
	ctx context.Context,
	server *socks5.Server,
	listener net.Listener,
	supervisor *tunnelSupervisor,
) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Serve(serveCtx, listener) }()
	select {
	case err := <-serverResult:
		return err
	case <-supervisor.Done():
		cancel()
		serveErr := <-serverResult
		if tunnelErr := supervisor.Err(); tunnelErr != nil {
			return fmt.Errorf("packet tunnel stopped: %w", tunnelErr)
		}
		if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
			return serveErr
		}
		return nil
	}
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
	lifetimeCtx := request.LifetimeContext
	if lifetimeCtx == nil {
		lifetimeCtx = ctx
	}
	packetTunnel, err := gp.NewSSLPacketTunnelWithLifetime(ctx, lifetimeCtx, conn, request.Session, request.Config)
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
