package app

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var errBlankServeListen = errors.New("serve listen address must not be blank")

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

func makeServeConfig(patch servePatch) (serveConfig, error) {
	timeout, err := time.ParseDuration(patch.Timeout.value)
	if err != nil {
		return serveConfig{}, fmt.Errorf("parse serve timeout: %w", err)
	}
	if strings.TrimSpace(patch.Listen.value) == "" {
		return serveConfig{}, fmt.Errorf("validate serve listen: %w", errBlankServeListen)
	}
	return serveConfig{
		listenAddr:        patch.Listen.value,
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
