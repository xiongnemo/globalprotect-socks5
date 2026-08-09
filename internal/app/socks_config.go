package app

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
)

const maxSOCKSConnections = 65535

var (
	errBlankServeListen       = errors.New("serve listen address must not be blank")
	errNonLoopbackOptIn       = errors.New("non-loopback listen requires --allow-non-loopback")
	errNonLoopbackAuth        = errors.New("non-loopback listen requires valid SOCKS5 authentication")
	errInvalidConnectionLimit = errors.New("SOCKS5 max connections must be between 1 and 65535")
)

type socksServeConfig struct {
	credentials      *socks5.Credentials
	handshakeTimeout time.Duration
	connectTimeout   time.Duration
	maxConnections   int
}

func parseSOCKSServeConfig(patch servePatch, allowNonLoopback bool) (socksServeConfig, error) {
	credentials, err := parseSOCKSCredentials(patch.SOCKSUsername.value, patch.SOCKSPassword.value)
	if err != nil {
		return socksServeConfig{}, err
	}
	handshakeTimeout, err := parsePositiveDuration("SOCKS5 handshake timeout", patch.HandshakeTimeout.value)
	if err != nil {
		return socksServeConfig{}, err
	}
	connectTimeout, err := parsePositiveDuration("SOCKS5 connect timeout", patch.ConnectTimeout.value)
	if err != nil {
		return socksServeConfig{}, err
	}
	maxConnections, err := strconv.Atoi(patch.MaxConnections.value)
	if err != nil || maxConnections < 1 || maxConnections > maxSOCKSConnections {
		return socksServeConfig{}, fmt.Errorf("validate SOCKS5 max connections: %w", errInvalidConnectionLimit)
	}
	if err := validateListenPolicy(patch.Listen.value, allowNonLoopback, credentials); err != nil {
		return socksServeConfig{}, err
	}
	return socksServeConfig{
		credentials: credentials, handshakeTimeout: handshakeTimeout,
		connectTimeout: connectTimeout, maxConnections: maxConnections,
	}, nil
}

func parseSOCKSCredentials(username, password string) (*socks5.Credentials, error) {
	if username == "" && password == "" {
		return nil, nil
	}
	credentials := socks5.Credentials{Username: username, Password: password}
	if err := socks5.ValidateCredentials(credentials); err != nil {
		return nil, fmt.Errorf("validate SOCKS5 credentials: %w", err)
	}
	return &credentials, nil
}

func parsePositiveDuration(name, raw string) (time.Duration, error) {
	duration, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("validate %s: must be positive", name)
	}
	return duration, nil
}

func validateListenPolicy(address string, allowNonLoopback bool, credentials *socks5.Credentials) error {
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("validate serve listen: %w", errBlankServeListen)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("validate serve listen address: %w", err)
	}
	if isLoopbackHost(host) {
		return nil
	}
	return validateNonLoopbackPolicy(allowNonLoopback, credentials)
}

func validateBoundListenAddress(address net.Addr, allowNonLoopback bool, credentials *socks5.Credentials) error {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("validate bound SOCKS5 listener: unsupported network")
	}
	if ip, ok := netip.AddrFromSlice(tcpAddress.IP); ok && ip.Unmap().IsLoopback() {
		return nil
	}
	return validateNonLoopbackPolicy(allowNonLoopback, credentials)
}

func validateNonLoopbackPolicy(allow bool, credentials *socks5.Credentials) error {
	if !allow {
		return fmt.Errorf("validate serve listen: %w", errNonLoopbackOptIn)
	}
	if credentials == nil {
		return fmt.Errorf("validate serve listen: %w", errNonLoopbackAuth)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.Unmap().IsLoopback()
}
