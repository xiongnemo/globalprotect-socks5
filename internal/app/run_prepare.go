package app

func (r Runner) prepareInvocation(cli cliInvocation) (preparedInvocation, error) {
	selection, err := selectConfig(cli.configPath, cli.noConfig, r.io.AutoConfig)
	if err != nil {
		return preparedInvocation{}, err
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
		prepared.serve, err = makeServeConfig(raw.serve)
	case commandParseAuth:
	}
	if err != nil {
		return preparedInvocation{}, err
	}
	return prepared, nil
}
