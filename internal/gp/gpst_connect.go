package gp

import (
	"context"
	"fmt"
	"net"
	"time"
)

// NewSSLPacketTunnel establishes a GPST tunnel whose handshake and runtime
// share the same context.
func NewSSLPacketTunnel(ctx context.Context, conn net.Conn, session GatewaySession, config TunnelConfig) (*SSLPacketTunnel, error) {
	return NewSSLPacketTunnelWithLifetime(ctx, ctx, conn, session, config)
}

// NewSSLPacketTunnelWithLifetime establishes a GPST tunnel using connectCtx
// only for the handshake and lifetimeCtx for the established tunnel.
func NewSSLPacketTunnelWithLifetime(connectCtx, lifetimeCtx context.Context, conn net.Conn, session GatewaySession, config TunnelConfig) (*SSLPacketTunnel, error) {
	options := defaultGPSTRuntimeOptions()
	options.rekeyAfter = config.RekeyAfter
	return newSSLPacketTunnelWithLifetime(connectCtx, lifetimeCtx, conn, session, config, options)
}

func newSSLPacketTunnel(ctx context.Context, conn net.Conn, session GatewaySession, config TunnelConfig, options gpstRuntimeOptions) (*SSLPacketTunnel, error) {
	return newSSLPacketTunnelWithLifetime(ctx, ctx, conn, session, config, options)
}

func newSSLPacketTunnelWithLifetime(connectCtx, lifetimeCtx context.Context, conn net.Conn, session GatewaySession, config TunnelConfig, options gpstRuntimeOptions) (*SSLPacketTunnel, error) {
	options = normalizeGPSTRuntimeOptions(options)
	request, err := sslTunnelRequest(session, config)
	if err != nil {
		return nil, err
	}
	handshakeCtx, cancelHandshake := context.WithTimeout(connectCtx, options.handshakeTimeout)
	defer cancelHandshake()
	if err := writeAllContext(handshakeCtx, conn, []byte(request)); err != nil {
		return nil, fmt.Errorf("write tunnel request: %w", err)
	}
	marker := make([]byte, len(gpstStartTunnel))
	if err := readFullContext(handshakeCtx, conn, marker); err != nil {
		return nil, fmt.Errorf("read tunnel marker: %w", err)
	}
	if string(marker) != gpstStartTunnel {
		return nil, fmt.Errorf("tunnel marker %q: %w", string(marker), ErrInvalidGPSTHandshake)
	}
	runtimeCtx, cancel := context.WithCancel(lifetimeCtx)
	now := time.Now()
	tunnel := &SSLPacketTunnel{
		conn: conn, ctx: runtimeCtx, cancel: cancel, lastRx: now, lastTx: now,
		started: now, options: options, writeLock: make(chan struct{}, 1),
	}
	tunnel.writeLock <- struct{}{}
	tunnel.wg.Add(1)
	go tunnel.monitor()
	return tunnel, nil
}

func normalizeGPSTRuntimeOptions(options gpstRuntimeOptions) gpstRuntimeOptions {
	if options.handshakeTimeout <= 0 {
		options.handshakeTimeout = 30 * time.Second
	}
	if options.dpdInterval <= 0 {
		options.dpdInterval = 10 * time.Second
	}
	if options.dpdTimeout <= options.dpdInterval {
		options.dpdTimeout = 2 * options.dpdInterval
	}
	if options.writeTimeout <= 0 {
		options.writeTimeout = 10 * time.Second
	}
	return options
}
