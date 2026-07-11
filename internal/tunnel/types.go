package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/link/channel"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
)

const (
	defaultMTU       = uint32(1500)
	packetQueueDepth = 1024
	nicID            = tcpip.NICID(1)
)

type PacketTunnel interface {
	ReadPacket(context.Context) ([]byte, error)
	WritePacket(context.Context, []byte) error
	Close() error
}

type Resolver interface {
	LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error)
}

type ResolverFunc func(ctx context.Context, network string, host string) ([]netip.Addr, error)

func (f ResolverFunc) LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type Config struct {
	Tunnel    PacketTunnel
	LocalAddr netip.Addr
	Resolver  Resolver
	MTU       uint32
}

type Dialer struct {
	stack    *stack.Stack
	linkEP   *channel.Endpoint
	tunnel   PacketTunnel
	resolver Resolver
	cancel   context.CancelFunc
	errMu    sync.RWMutex
	err      error
	wg       sync.WaitGroup
	once     sync.Once
	shutdown sync.Once
}

func NewDialer(ctx context.Context, cfg Config) (*Dialer, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("create tunnel dialer: %w", err)
	}
	resolved, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	s, linkEP, err := newNetstack(resolved.LocalAddr, resolved.MTU)
	if err != nil {
		return nil, err
	}
	pumpCtx, cancel := context.WithCancel(ctx)
	d := &Dialer{stack: s, linkEP: linkEP, tunnel: resolved.Tunnel, resolver: resolved.Resolver, cancel: cancel}
	d.wg.Add(2)
	go d.readPackets(pumpCtx)
	go d.writePackets(pumpCtx)
	return d, nil
}

func (d *Dialer) Close() error {
	var closeErr error
	d.once.Do(func() {
		d.cancel()
		d.shutdownNetstack()
		if err := d.tunnel.Close(); err != nil {
			closeErr = fmt.Errorf("close packet tunnel: %w", err)
		}
		d.wg.Wait()
		d.stack.Wait()
	})
	return closeErr
}

func (d *Dialer) fail(err error) {
	d.errMu.Lock()
	if d.err == nil {
		d.err = err
	}
	d.errMu.Unlock()
	d.cancel()
	d.shutdownNetstack()
}

func (d *Dialer) terminalError() error {
	d.errMu.RLock()
	defer d.errMu.RUnlock()
	return d.err
}

func (d *Dialer) shutdownNetstack() {
	d.shutdown.Do(func() {
		d.linkEP.Close()
		d.stack.Close()
	})
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.Tunnel == nil {
		return Config{}, fmt.Errorf("packet tunnel: %w", ErrInvalidConfig)
	}
	if !cfg.LocalAddr.IsValid() {
		return Config{}, fmt.Errorf("local address: %w", ErrInvalidConfig)
	}
	if !cfg.LocalAddr.Is4() {
		return Config{}, fmt.Errorf("local address %s: %w", cfg.LocalAddr, ErrIPv6Unsupported)
	}
	if cfg.MTU == 0 {
		cfg.MTU = defaultMTU
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	return cfg, nil
}

func newNetstack(localAddr netip.Addr, mtu uint32) (*stack.Stack, *channel.Endpoint, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	linkEP := channel.New(packetQueueDepth, mtu, "")
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		linkEP.Close()
		s.Destroy()
		return nil, nil, fmt.Errorf("create tunnel netstack NIC: %w", netstackError{message: err.String()})
	}
	protocolAddr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpipAddr(localAddr).WithPrefix()}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		linkEP.Close()
		s.Destroy()
		return nil, nil, fmt.Errorf("add tunnel netstack address: %w", netstackError{message: err.String()})
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	return s, linkEP, nil
}
