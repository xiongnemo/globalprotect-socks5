package app

import (
	"fmt"

	"github.com/xiongnemo/globalprotect-socks5/internal/userdirs"
)

func (r Runner) prepareInvocation(cli cliInvocation) (preparedInvocation, error) {
	selection, err := selectConfig(cli.configPath, cli.noConfig, r.io.AutoConfig, r.userDirs())
	if err != nil {
		return preparedInvocation{}, err
	}
	if selection.legacyNotice != "" {
		// User-facing stderr, once per run; never stdout or the JSON log.
		fmt.Fprintln(r.io.Stderr, selection.legacyNotice)
	}

	var file fileConfig
	if selection.path != "" {
		file, err = loadConfig(selection.path, selection.allowMissing)
		if err != nil {
			return preparedInvocation{}, err
		}
	}

	raw, err := resolveRawInvocation(cli, file, lookupEnvFunc(r.io.LookupEnv))
	if err != nil {
		return preparedInvocation{}, err
	}
	level, err := parseLogLevel(raw.logLevel.value)
	if err != nil {
		return preparedInvocation{}, err
	}

	prepared := preparedInvocation{
		command:   raw.command,
		arguments: append([]string(nil), cli.arguments...),
		logLevel:  level,
	}
	switch raw.command {
	case commandProbe:
		prepared.probe = makeProbeConfig(raw.probe)
	case commandAuth:
		prepared.auth, err = makeAuthConfig(raw.auth)
	case commandServe:
		prepared.serve, err = makeServeConfig(raw.serve, raw.allowNonLoopback)
	case commandParseAuth:
	}
	if err != nil {
		return preparedInvocation{}, err
	}
	return prepared, nil
}

// userDirs is the XDG resolver over the injected environment: no variables
// without LookupEnv, no home without HomeDir.
func (r Runner) userDirs() userdirs.Env {
	return userdirs.Env{LookupEnv: r.io.LookupEnv, HomeDir: r.io.HomeDir}
}
