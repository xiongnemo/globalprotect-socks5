package gp

import (
	"encoding/xml"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type configXML struct {
	Result        tunnelConfigXML `xml:"result"`
	IP            string          `xml:"ip-address"`
	SSLTunnelURL  string          `xml:"ssl-tunnel-url"`
	MTU           string          `xml:"mtu"`
	Lifetime      string          `xml:"lifetime"`
	TunnelTimeout string          `xml:"timeout"`
	DNS           []string        `xml:"dns>member"`
	DNSSuffixes   []string        `xml:"dns-suffix>member"`
	IncludeRoutes []string        `xml:"access-routes>member"`
	ExcludeRoutes []string        `xml:"exclude-access-routes>member"`
}

type tunnelConfigXML struct {
	IP            string   `xml:"ip-address"`
	SSLTunnelURL  string   `xml:"ssl-tunnel-url"`
	MTU           string   `xml:"mtu"`
	Lifetime      string   `xml:"lifetime"`
	TunnelTimeout string   `xml:"timeout"`
	DNS           []string `xml:"dns>member"`
	DNSSuffixes   []string `xml:"dns-suffix>member"`
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
			MTU:           parsed.MTU,
			Lifetime:      parsed.Lifetime,
			TunnelTimeout: parsed.TunnelTimeout,
			DNS:           parsed.DNS,
			DNSSuffixes:   parsed.DNSSuffixes,
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
	mtu, err := parseOptionalUint32(result.MTU)
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("gateway config mtu: %w", err)
	}
	authLifetime, err := parseOptionalSeconds(result.Lifetime)
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("gateway config lifetime: %w", err)
	}
	rekeyAfter, err := parseOptionalSeconds(result.TunnelTimeout)
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("gateway config timeout: %w", err)
	}
	if rekeyAfter > time.Minute {
		rekeyAfter -= time.Minute
	}
	return TunnelConfig{
		IP:            ip,
		SSLTunnelURL:  strings.TrimSpace(result.SSLTunnelURL),
		MTU:           mtu,
		AuthLifetime:  authLifetime,
		RekeyAfter:    rekeyAfter,
		DNS:           dns,
		DNSSuffixes:   normalizeStrings(result.DNSSuffixes),
		IncludeRoutes: includeRoutes,
		ExcludeRoutes: excludeRoutes,
	}, nil
}

func parseOptionalUint32(raw string) (uint32, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(trimmed, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value), nil
}

func parseOptionalSeconds(raw string) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	seconds, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || seconds < 0 {
		if err == nil {
			err = fmt.Errorf("duration must not be negative")
		}
		return 0, err
	}
	if seconds > int64((1<<63-1)/time.Second) {
		return 0, fmt.Errorf("duration overflows")
	}
	return time.Duration(seconds) * time.Second, nil
}

func normalizeStrings(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	return normalized
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
