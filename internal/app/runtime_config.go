package app

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
)

type probeConfig struct {
	portalRaw    string
	hostID       string
	ssoFile      string
	debugLogPath string
}

type authConfig struct {
	portalRaw         string
	hostID            string
	browserRaw        string
	browserPath       string
	browserProfileDir string
	timeout           time.Duration
	debugLogPath      string
}

type preparedInvocation struct {
	command   commandName
	arguments []string
	logLevel  logLevel
	probe     probeConfig
	auth      authConfig
	serve     serveConfig
}

type serveConfig struct {
	listenAddr        string
	socksCredentials  *socks5.Credentials
	handshakeTimeout  time.Duration
	connectTimeout    time.Duration
	maxConnections    int
	allowNonLoopback  bool
	dnsMode           serveDNSMode
	dnsServers        []netip.Addr
	portalRaw         string
	gatewayRaw        string
	hostID            string
	browserRaw        string
	browserPath       string
	browserProfileDir string
	timeout           time.Duration
	debugLogPath      string
}

func makeProbeConfig(patch probePatch) probeConfig {
	return probeConfig{
		portalRaw:    patch.Portal.value,
		hostID:       patch.HostID.value,
		ssoFile:      patch.SSOFile.value,
		debugLogPath: patch.DebugLog.value,
	}
}

func makeAuthConfig(patch authPatch) (authConfig, error) {
	timeout, err := time.ParseDuration(patch.Timeout.value)
	if err != nil {
		return authConfig{}, fmt.Errorf("parse auth timeout: %w", err)
	}
	return authConfig{
		portalRaw:         patch.Portal.value,
		hostID:            patch.HostID.value,
		browserRaw:        patch.Browser.value,
		browserPath:       patch.BrowserPath.value,
		browserProfileDir: patch.BrowserProfileDir.value,
		timeout:           timeout,
		debugLogPath:      patch.DebugLog.value,
	}, nil
}

func makeServeConfig(patch servePatch, allowNonLoopback bool) (serveConfig, error) {
	timeout, err := time.ParseDuration(patch.Timeout.value)
	if err != nil {
		return serveConfig{}, fmt.Errorf("parse serve timeout: %w", err)
	}
	socksConfig, err := parseSOCKSServeConfig(patch, allowNonLoopback)
	if err != nil {
		return serveConfig{}, err
	}
	dnsConfig, err := parseServeDNSConfig(patch)
	if err != nil {
		return serveConfig{}, err
	}
	if strings.TrimSpace(patch.Portal.value) == "" && strings.TrimSpace(patch.Gateway.value) != "" {
		return serveConfig{}, fmt.Errorf("validate serve gateway: a gateway requires a portal")
	}
	if strings.TrimSpace(patch.Portal.value) == "" && len(dnsConfig.servers) > 0 {
		return serveConfig{}, fmt.Errorf("validate serve DNS: custom DNS servers require a portal")
	}
	return serveConfig{
		listenAddr:        patch.Listen.value,
		socksCredentials:  socksConfig.credentials,
		handshakeTimeout:  socksConfig.handshakeTimeout,
		connectTimeout:    socksConfig.connectTimeout,
		maxConnections:    socksConfig.maxConnections,
		allowNonLoopback:  allowNonLoopback,
		dnsMode:           dnsConfig.mode,
		dnsServers:        dnsConfig.servers,
		portalRaw:         patch.Portal.value,
		gatewayRaw:        patch.Gateway.value,
		hostID:            patch.HostID.value,
		browserRaw:        patch.Browser.value,
		browserPath:       patch.BrowserPath.value,
		browserProfileDir: patch.BrowserProfileDir.value,
		timeout:           timeout,
		debugLogPath:      patch.DebugLog.value,
	}, nil
}
