package app

import (
	"errors"
	"fmt"
	"strings"
)

var errBlankServePortalOverride = errors.New("blank serve portal override would clear a lower-precedence portal")

const defaultConfigPath = "config.yaml"

type configSelection struct {
	path         string
	allowMissing bool
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

func selectConfig(cliPath optionalString, noConfig, autoConfig bool) (configSelection, error) {
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
		return configSelection{path: defaultConfigPath, allowMissing: true}, nil
	}
	return configSelection{}, nil
}
