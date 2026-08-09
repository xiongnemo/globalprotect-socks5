package tunnel

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/link/channel"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/udp"
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
	Tunnel           PacketTunnel
	LocalAddr        netip.Addr
	Resolver         Resolver
	DNSServers       []netip.Addr
	DNSSearchDomains []string
	MTU              uint32
}

type Dialer struct {
	stack    *stack.Stack
	linkEP   *channel.Endpoint
	tunnel   PacketTunnel
	resolver Resolver
	cancel   context.CancelFunc
	stateMu  sync.RWMutex
	done     chan struct{}
	doneErr  error
	terminal bool
	wg       sync.WaitGroup
	once     sync.Once
	closeErr error
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
	resolver := resolved.Resolver
	if resolver == nil {
		resolver = newTunnelDNSResolver(s, resolved.DNSServers, resolved.DNSSearchDomains)
	}
	d := &Dialer{
		stack: s, linkEP: linkEP, tunnel: resolved.Tunnel, resolver: resolver,
		cancel: cancel, done: make(chan struct{}),
	}
	d.wg.Add(3)
	go d.readPackets(pumpCtx)
	go d.writePackets(pumpCtx)
	go d.watchContext(pumpCtx)
	return d, nil
}

// Done is closed when the dialer stops because its context was canceled, it
// was closed, or a packet pump failed.
func (d *Dialer) Done() <-chan struct{} {
	return d.done
}

// Err reports the packet-pump failure that stopped the dialer. It is nil for
// explicit Close and parent-context cancellation, and is stable after Done is
// closed.
func (d *Dialer) Err() error {
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	return d.doneErr
}

func (d *Dialer) Close() error {
	d.once.Do(func() {
		d.terminate(nil)
		d.cancel()
		d.shutdownNetstack()
		if err := d.tunnel.Close(); err != nil {
			d.closeErr = fmt.Errorf("close packet tunnel: %w", err)
		}
		d.wg.Wait()
		d.stack.Wait()
	})
	return d.closeErr
}

func (d *Dialer) fail(err error) {
	d.terminate(err)
	d.cancel()
	d.shutdownNetstack()
}

func (d *Dialer) terminalError() error {
	return d.Err()
}

func (d *Dialer) terminate(err error) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	if d.terminal {
		return
	}
	d.terminal = true
	d.doneErr = err
	close(d.done)
}

func (d *Dialer) watchContext(ctx context.Context) {
	defer d.wg.Done()
	<-ctx.Done()
	d.terminate(nil)
	d.shutdownNetstack()
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
	dnsServers, err := normalizeDNSServers(cfg.DNSServers)
	if err != nil {
		return Config{}, err
	}
	cfg.DNSServers = dnsServers
	cfg.DNSSearchDomains = normalizeDNSSearchDomains(cfg.DNSSearchDomains)
	return cfg, nil
}

func newNetstack(localAddr netip.Addr, mtu uint32) (*stack.Stack, *channel.Endpoint, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
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
