package app

const (
	envLogLevel          = "GP_SOCKS_LOG_LEVEL"
	envListen            = "GP_SOCKS_LISTEN"
	envSOCKSUsername     = "GP_SOCKS_USERNAME"
	envSOCKSPassword     = "GP_SOCKS_PASSWORD"
	envHandshakeTimeout  = "GP_SOCKS_HANDSHAKE_TIMEOUT"
	envConnectTimeout    = "GP_SOCKS_CONNECT_TIMEOUT"
	envMaxConnections    = "GP_SOCKS_MAX_CONNECTIONS"
	envPortal            = "GP_SOCKS_PORTAL"
	envGateway           = "GP_SOCKS_GATEWAY"
	envDNSMode           = "GP_SOCKS_DNS_MODE"
	envDNSServers        = "GP_SOCKS_DNS_SERVERS"
	envHostID            = "GP_SOCKS_HOST_ID"
	envBrowser           = "GP_SOCKS_BROWSER"
	envBrowserPath       = "GP_SOCKS_BROWSER_PATH"
	envBrowserProfileDir = "GP_SOCKS_BROWSER_PROFILE_DIR"
	envTimeout           = "GP_SOCKS_TIMEOUT"
	envSSOFile           = "GP_SOCKS_SSO_FILE"
	envDebugLog          = "GP_SOCKS_DEBUG_LOG"
)

func environmentFor(command commandName, lookupEnv lookupEnvFunc) rawInvocation {
	environment := rawInvocation{
		command:  command,
		logLevel: lookupOptionalString(lookupEnv, envLogLevel),
	}

	switch command {
	case commandProbe:
		environment.probe = probePatch{
			Portal:   lookupOptionalString(lookupEnv, envPortal),
			HostID:   lookupOptionalString(lookupEnv, envHostID),
			SSOFile:  lookupOptionalString(lookupEnv, envSSOFile),
			DebugLog: lookupOptionalString(lookupEnv, envDebugLog),
		}
	case commandAuth:
		environment.auth = authPatch{
			Portal:            lookupOptionalString(lookupEnv, envPortal),
			HostID:            lookupOptionalString(lookupEnv, envHostID),
			Browser:           lookupOptionalString(lookupEnv, envBrowser),
			BrowserPath:       lookupOptionalString(lookupEnv, envBrowserPath),
			BrowserProfileDir: lookupOptionalString(lookupEnv, envBrowserProfileDir),
			Timeout:           lookupOptionalString(lookupEnv, envTimeout),
			DebugLog:          lookupOptionalString(lookupEnv, envDebugLog),
		}
	case commandServe:
		environment.serve = servePatch{
			Listen:            lookupOptionalString(lookupEnv, envListen),
			SOCKSUsername:     lookupOptionalString(lookupEnv, envSOCKSUsername),
			SOCKSPassword:     lookupOptionalString(lookupEnv, envSOCKSPassword),
			HandshakeTimeout:  lookupOptionalString(lookupEnv, envHandshakeTimeout),
			ConnectTimeout:    lookupOptionalString(lookupEnv, envConnectTimeout),
			MaxConnections:    lookupOptionalString(lookupEnv, envMaxConnections),
			Portal:            lookupOptionalString(lookupEnv, envPortal),
			Gateway:           lookupOptionalString(lookupEnv, envGateway),
			DNSMode:           lookupOptionalString(lookupEnv, envDNSMode),
			DNSServers:        lookupOptionalString(lookupEnv, envDNSServers),
			HostID:            lookupOptionalString(lookupEnv, envHostID),
			Browser:           lookupOptionalString(lookupEnv, envBrowser),
			BrowserPath:       lookupOptionalString(lookupEnv, envBrowserPath),
			BrowserProfileDir: lookupOptionalString(lookupEnv, envBrowserProfileDir),
			Timeout:           lookupOptionalString(lookupEnv, envTimeout),
			DebugLog:          lookupOptionalString(lookupEnv, envDebugLog),
		}
	case commandParseAuth:
	}

	return environment
}

func lookupOptionalString(lookupEnv lookupEnvFunc, name string) optionalString {
	value, present := lookupEnv(name)
	return optionalString{value: value, present: present}
}
