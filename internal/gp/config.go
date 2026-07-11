package gp

import (
	"encoding/xml"
	"fmt"
	"net/netip"
	"strings"
)

type configXML struct {
	Result        tunnelConfigXML `xml:"result"`
	IP            string          `xml:"ip-address"`
	SSLTunnelURL  string          `xml:"ssl-tunnel-url"`
	DNS           []string        `xml:"dns>member"`
	IncludeRoutes []string        `xml:"access-routes>member"`
	ExcludeRoutes []string        `xml:"exclude-access-routes>member"`
}

type tunnelConfigXML struct {
	IP            string   `xml:"ip-address"`
	SSLTunnelURL  string   `xml:"ssl-tunnel-url"`
	DNS           []string `xml:"dns>member"`
	IncludeRoutes []string `xml:"access-routes>member"`
	ExcludeRoutes []string `xml:"exclude-access-routes>member"`
}

func parseTunnelConfig(body []byte) (TunnelConfig, error) {
	var parsed configXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return TunnelConfig{}, fmt.Errorf("decode gateway config xml: %w", err)
	}
	result := parsed.Result
	if result.IP == "" && result.SSLTunnelURL == "" {
		result = tunnelConfigXML{
			IP:            parsed.IP,
			SSLTunnelURL:  parsed.SSLTunnelURL,
			DNS:           parsed.DNS,
			IncludeRoutes: parsed.IncludeRoutes,
			ExcludeRoutes: parsed.ExcludeRoutes,
		}
	}
	ip, err := parseOptionalAddr(result.IP)
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("gateway config ip: %w", err)
	}
	dns, err := parseAddrList(result.DNS)
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("gateway config dns: %w", err)
	}
	includeRoutes, err := parsePrefixList(result.IncludeRoutes)
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("gateway config include routes: %w", err)
	}
	excludeRoutes, err := parsePrefixList(result.ExcludeRoutes)
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("gateway config exclude routes: %w", err)
	}
	return TunnelConfig{
		IP:            ip,
		SSLTunnelURL:  strings.TrimSpace(result.SSLTunnelURL),
		DNS:           dns,
		IncludeRoutes: includeRoutes,
		ExcludeRoutes: excludeRoutes,
	}, nil
}

func parseOptionalAddr(raw string) (netip.Addr, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func parseAddrList(values []string) ([]netip.Addr, error) {
	addrs := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		addr, err := netip.ParseAddr(trimmed)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func parsePrefixList(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}
