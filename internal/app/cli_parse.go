package app

import (
	"flag"
	"fmt"
	"io"
)

func parseCLIInvocation(args []string, stderr io.Writer) (cliInvocation, error) {
	flags := flag.NewFlagSet("gp-socks", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.String("config", "", "YAML configuration file; overrides automatic config.yaml discovery")
	flags.Bool("no-config", false, "disable automatic and explicit configuration files")
	flags.String("log-level", "", "application log level: error, warn, info, or debug")
	if err := flags.Parse(args); err != nil {
		return cliInvocation{}, fmt.Errorf("parse root flags: %w", err)
	}

	var invocation cliInvocation
	flags.Visit(func(visited *flag.Flag) {
		switch visited.Name {
		case "config":
			invocation.configPath = presentString(visited.Value.String())
		case "no-config":
			invocation.noConfig = visited.Value.String() == "true"
		case "log-level":
			invocation.logLevel = presentString(visited.Value.String())
		}
	})

	remaining := flags.Args()
	if len(remaining) == 0 {
		return invocation, ErrUsage
	}
	invocation.command = commandName(remaining[0])
	commandArgs := remaining[1:]

	var err error
	switch invocation.command {
	case commandProbe:
		invocation.probe, err = parseProbeFlags(commandArgs, stderr)
	case commandAuth:
		invocation.auth, err = parseAuthFlags(commandArgs, stderr)
	case commandServe:
		invocation.serve, err = parseServeFlags(commandArgs, stderr)
	case commandParseAuth:
		invocation.arguments = append([]string(nil), commandArgs...)
	default:
		return invocation, ErrUsage
	}
	return invocation, err
}

func parseProbeFlags(args []string, stderr io.Writer) (probePatch, error) {
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.String("portal", "", "GlobalProtect portal URL")
	flags.String("host-id", "gp-socks", "stable GlobalProtect host-id")
	flags.String("sso-file", "", "write SAML POST HTML to this file")
	flags.String("debug-log", "", "write redacted GlobalProtect HTTP debug JSONL to this file")
	if err := flags.Parse(args); err != nil {
		return probePatch{}, fmt.Errorf("parse probe flags: %w", err)
	}

	var patch probePatch
	flags.Visit(func(visited *flag.Flag) {
		value := presentString(visited.Value.String())
		switch visited.Name {
		case "portal":
			patch.Portal = value
		case "host-id":
			patch.HostID = value
		case "sso-file":
			patch.SSOFile = value
		case "debug-log":
			patch.DebugLog = value
		}
	})
	return patch, nil
}

func parseAuthFlags(args []string, stderr io.Writer) (authPatch, error) {
	flags := flag.NewFlagSet("auth", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.String("portal", "", "GlobalProtect portal URL")
	flags.String("host-id", "gp-socks", "stable GlobalProtect host-id")
	flags.String("browser", "auto", "browser: auto, chrome, or edge")
	flags.String("browser-path", "", "explicit Chrome or Edge executable path")
	flags.String("browser-profile-dir", "", "explicit persistent Chrome/Edge profile directory for browser SSO")
	flags.Duration("timeout", defaultBrowserAuthTimeout, "maximum time to wait for browser SSO")
	flags.String("debug-log", "", "write redacted GlobalProtect HTTP debug JSONL to this file")
	if err := flags.Parse(args); err != nil {
		return authPatch{}, fmt.Errorf("parse auth flags: %w", err)
	}

	var patch authPatch
	flags.Visit(func(visited *flag.Flag) {
		value := presentString(visited.Value.String())
		switch visited.Name {
		case "portal":
			patch.Portal = value
		case "host-id":
			patch.HostID = value
		case "browser":
			patch.Browser = value
		case "browser-path":
			patch.BrowserPath = value
		case "browser-profile-dir":
			patch.BrowserProfileDir = value
		case "timeout":
			patch.Timeout = value
		case "debug-log":
			patch.DebugLog = value
		}
	})
	return patch, nil
}

func parseServeFlags(args []string, stderr io.Writer) (servePatch, error) {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	flags.String("portal", "", "GlobalProtect portal URL; enables VPN-backed egress")
	flags.String("gateway", "", "GlobalProtect gateway URL; overrides portal-selected gateway")
	flags.String("host-id", "gp-socks", "stable GlobalProtect host-id")
	flags.String("browser", "auto", "browser: auto, chrome, or edge")
	flags.String("browser-path", "", "explicit Chrome or Edge executable path")
	flags.String("browser-profile-dir", "", "explicit persistent Chrome/Edge profile directory for browser SSO")
	flags.Duration("timeout", defaultBrowserAuthTimeout, "maximum time to wait for browser SSO")
	flags.String("debug-log", "", "write redacted GlobalProtect HTTP debug JSONL to this file")
	if err := flags.Parse(args); err != nil {
		return servePatch{}, fmt.Errorf("parse serve flags: %w", err)
	}

	var patch servePatch
	flags.Visit(func(visited *flag.Flag) {
		value := presentString(visited.Value.String())
		switch visited.Name {
		case "listen":
			patch.Listen = value
		case "portal":
			patch.Portal = value
		case "gateway":
			patch.Gateway = value
		case "host-id":
			patch.HostID = value
		case "browser":
			patch.Browser = value
		case "browser-path":
			patch.BrowserPath = value
		case "browser-profile-dir":
			patch.BrowserProfileDir = value
		case "timeout":
			patch.Timeout = value
		case "debug-log":
			patch.DebugLog = value
		}
	})
	return patch, nil
}
