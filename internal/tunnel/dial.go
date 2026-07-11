package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
)

func (d *Dialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	if err := d.terminalError(); err != nil {
		return nil, err
	}
	if err := ensureTCP4Network(network); err != nil {
		return nil, err
	}
	target, err := d.resolveTarget(ctx, address)
	if err != nil {
		return nil, err
	}
	conn, err := gonet.DialContextTCP(ctx, d.stack, target, ipv4.ProtocolNumber)
	if err != nil {
		if terminalErr := d.terminalError(); terminalErr != nil {
			return nil, terminalErr
		}
		return nil, fmt.Errorf("dial %s through packet tunnel: %w", address, err)
	}
	if err := d.terminalError(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func ensureTCP4Network(network string) error {
	switch network {
	case "tcp", "tcp4":
		return nil
	case "tcp6":
		return fmt.Errorf("network %s: %w", network, ErrIPv6Unsupported)
	default:
		return fmt.Errorf("network %s: %w", network, ErrUnsupportedNetwork)
	}
}

func (d *Dialer) resolveTarget(ctx context.Context, address string) (tcpip.FullAddress, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return tcpip.FullAddress{}, fmt.Errorf("parse target address %q: %w", address, err)
	}
	port, err := parsePort(portText)
	if err != nil {
		return tcpip.FullAddress{}, err
	}
	addr, err := d.resolveHost(ctx, host)
	if err != nil {
		return tcpip.FullAddress{}, err
	}
	return tcpip.FullAddress{NIC: nicID, Addr: tcpipAddr(addr), Port: port}, nil
}

func parsePort(raw string) (uint16, error) {
	port, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("parse target port %q: %w", raw, err)
	}
	return uint16(port), nil
}

func (d *Dialer) resolveHost(ctx context.Context, host string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(host)
	if err == nil {
		if !addr.Is4() {
			return netip.Addr{}, fmt.Errorf("target address %s: %w", addr, ErrIPv6Unsupported)
		}
		return addr, nil
	}
	addrs, err := d.resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve target host %s: %w", host, err)
	}
	for _, resolved := range addrs {
		if resolved.Is4() {
			return resolved, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("resolve target host %s: %w", host, ErrNoIPv4Address)
}
