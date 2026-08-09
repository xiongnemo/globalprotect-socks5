package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
)

const (
	dnsPort          = uint16(53)
	dnsServerTimeout = 2 * time.Second
)

type tunnelDNSResolver struct {
	stack         *stack.Stack
	servers       []netip.Addr
	searchDomains []string
}

func newTunnelDNSResolver(s *stack.Stack, servers []netip.Addr, searchDomains []string) Resolver {
	return &tunnelDNSResolver{stack: s, servers: servers, searchDomains: searchDomains}
}

func (r *tunnelDNSResolver) LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, fmt.Errorf("dns lookup network %q: %w", network, ErrUnsupportedNetwork)
	}
	if len(r.servers) == 0 {
		return nil, fmt.Errorf("resolve %s: %w", host, ErrDNSUnavailable)
	}
	var notFound error
	for _, name := range dnsLookupNames(host, r.searchDomains) {
		addrs, err := r.lookupName(ctx, name)
		if err == nil {
			return addrs, nil
		}
		if !isDNSNotFound(err) {
			return nil, err
		}
		notFound = err
	}
	return nil, notFound
}

func (r *tunnelDNSResolver) lookupName(ctx context.Context, name string) ([]netip.Addr, error) {
	serverErrors := make([]error, 0, len(r.servers))
	for _, server := range r.servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		serverCtx, cancel := context.WithTimeout(ctx, dnsServerTimeout)
		addrs, err := r.serverResolver(server).LookupNetIP(serverCtx, "ip4", name)
		cancel()
		if err == nil {
			return addrs, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if isDNSNotFound(err) {
			return nil, err
		}
		serverErrors = append(serverErrors, fmt.Errorf("vpn dns server %s: %w", server, err))
	}
	return nil, fmt.Errorf("resolve %s through vpn dns: %w", name, errors.Join(serverErrors...))
}

func (r *tunnelDNSResolver) serverResolver(server netip.Addr) *net.Resolver {
	target := tcpip.FullAddress{NIC: nicID, Addr: tcpipAddr(server), Port: dnsPort}
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			conn, err := r.dialServer(ctx, network, target)
			if err != nil {
				return nil, fmt.Errorf("dial vpn dns server %s over %s: %w", server, network, err)
			}
			return conn, nil
		},
	}
}

func (r *tunnelDNSResolver) dialServer(ctx context.Context, network string, target tcpip.FullAddress) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch network {
	case "udp", "udp4":
		return gonet.DialUDP(r.stack, nil, &target, ipv4.ProtocolNumber)
	case "tcp", "tcp4":
		return gonet.DialContextTCP(ctx, r.stack, target, ipv4.ProtocolNumber)
	default:
		return nil, fmt.Errorf("dns transport %q: %w", network, ErrUnsupportedNetwork)
	}
}

func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func normalizeDNSServers(servers []netip.Addr) ([]netip.Addr, error) {
	normalized := make([]netip.Addr, 0, len(servers))
	seen := make(map[netip.Addr]struct{}, len(servers))
	for _, server := range servers {
		if !server.IsValid() {
			return nil, fmt.Errorf("dns server: %w", ErrInvalidConfig)
		}
		if !server.Is4() {
			return nil, fmt.Errorf("dns server %s: %w", server, ErrIPv6Unsupported)
		}
		server = server.Unmap()
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		normalized = append(normalized, server)
	}
	return normalized, nil
}

func normalizeDNSSearchDomains(domains []string) []string {
	normalized := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		domain = strings.Trim(strings.TrimSpace(domain), ".")
		key := strings.ToLower(domain)
		if domain == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, domain)
	}
	return normalized
}

func dnsLookupNames(host string, searchDomains []string) []string {
	host = strings.TrimSpace(host)
	if strings.HasSuffix(host, ".") {
		return []string{host}
	}
	names := make([]string, 0, len(searchDomains)+1)
	if strings.Contains(host, ".") {
		names = append(names, host+".")
	}
	for _, domain := range searchDomains {
		names = append(names, host+"."+domain+".")
	}
	if !strings.Contains(host, ".") || len(names) == 0 {
		names = append(names, host+".")
	}
	return names
}
