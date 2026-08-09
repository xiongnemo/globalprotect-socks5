package app

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

type serveDNSMode string

const (
	serveDNSModeVPN    serveDNSMode = "vpn"
	serveDNSModeSystem serveDNSMode = "system"
)

var (
	errInvalidDNSMode   = errors.New("DNS mode must be vpn or system")
	errSystemCustomDNS  = errors.New("custom DNS servers require vpn DNS mode")
	errInvalidDNSServer = errors.New("DNS servers must be IPv4 address literals")
)

type serveDNSConfig struct {
	mode    serveDNSMode
	servers []netip.Addr
}

func parseServeDNSConfig(patch servePatch) (serveDNSConfig, error) {
	mode := serveDNSMode(strings.ToLower(strings.TrimSpace(patch.DNSMode.value)))
	if mode != serveDNSModeVPN && mode != serveDNSModeSystem {
		return serveDNSConfig{}, fmt.Errorf("validate serve DNS mode: %w", errInvalidDNSMode)
	}
	servers, err := parseDNSServers(patch.DNSServers.value)
	if err != nil {
		return serveDNSConfig{}, err
	}
	if mode == serveDNSModeSystem && len(servers) > 0 {
		return serveDNSConfig{}, fmt.Errorf("validate serve DNS servers: %w", errSystemCustomDNS)
	}
	return serveDNSConfig{mode: mode, servers: servers}, nil
}

func parseDNSServers(raw string) ([]netip.Addr, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' })
	servers := make([]netip.Addr, 0, len(parts))
	seen := make(map[netip.Addr]struct{}, len(parts))
	for _, part := range parts {
		server, err := netip.ParseAddr(part)
		if err != nil || !server.Is4() {
			return nil, fmt.Errorf("validate serve DNS servers: %w", errInvalidDNSServer)
		}
		server = server.Unmap()
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		servers = append(servers, server)
	}
	return servers, nil
}
