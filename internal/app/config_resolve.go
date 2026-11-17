package app

import (
	"errors"
	"fmt"
	"strings"

	"github.com/xiongnemo/globalprotect-socks5/internal/userdirs"
)

var errBlankServePortalOverride = errors.New("blank serve portal override would clear a lower-precedence portal")

type configSelection struct {
	path         string
	allowMissing bool
	// legacyNotice is the line to print on stderr when automatic discovery
	// falls back to ./config.yaml from older versions.
	legacyNotice string
}

func resolveRawInvocation(cli cliInvocation, file fileConfig, lookupEnv lookupEnvFunc) (rawInvocation, error) {
	defaults := defaultsFor(cli.command)
	environment := environmentFor(cli.command, lookupEnv)
	resolved := defaults
	resolved.logLevel = mergeOptional(defaults.logLevel, file.LogLevel, environment.logLevel, cli.logLevel)

	switch cli.command {
	case commandProbe:
		resolved.probe = mergeProbe(defaults.probe, file.Probe, environment.probe, cli.probe)
	case commandAuth:
		resolved.auth = mergeAuth(defaults.auth, file.Auth, environment.auth, cli.auth)
	case commandServe:
		resolved.serve = mergeServe(defaults.serve, file.Serve, environment.serve, cli.serve)
		resolved.allowNonLoopback = cli.allowNonLoopback
		if strings.TrimSpace(resolved.serve.Portal.value) == "" {
			lowerPortalNonblank := strings.TrimSpace(defaults.serve.Portal.value) != "" ||
				file.Serve.Portal.present && strings.TrimSpace(file.Serve.Portal.value) != ""
			blankPortalOverride := environment.serve.Portal.present
			if cli.serve.Portal.present {
				blankPortalOverride = true
				lowerPortalNonblank = lowerPortalNonblank ||
					environment.serve.Portal.present && strings.TrimSpace(environment.serve.Portal.value) != ""
			}
			if blankPortalOverride && lowerPortalNonblank {
				return rawInvocation{}, fmt.Errorf("resolve serve portal: %w", errBlankServePortalOverride)
			}
		}
	case commandParseAuth:
	}

	return resolved, nil
}

// selectConfig picks the configuration file. Automatic discovery takes
// $XDG_CONFIG_HOME/gp-socks/config.yaml, else ./config.yaml where older
// versions looked, and is optional either way.
func selectConfig(cliPath optionalString, noConfig, autoConfig bool, dirs userdirs.Env) (configSelection, error) {
	if cliPath.present && noConfig {
		return configSelection{}, fmt.Errorf("--config and --no-config are mutually exclusive")
	}
	if noConfig {
		return configSelection{}, nil
	}
	if cliPath.present {
		if strings.TrimSpace(cliPath.value) == "" {
			return configSelection{}, fmt.Errorf("config path must not be blank")
		}
		return configSelection{path: cliPath.value}, nil
	}
	if autoConfig {
		choice, err := dirs.ResolveConfig()
		if err != nil {
			return configSelection{}, fmt.Errorf("locate config: %w", err)
		}
		selection := configSelection{path: choice.Path, allowMissing: true}
		if choice.Legacy {
			selection.legacyNotice = choice.LegacyNotice()
		}
		return selection, nil
	}
	return configSelection{}, nil
}
