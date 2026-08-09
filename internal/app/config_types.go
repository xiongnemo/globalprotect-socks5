package app

type commandName string

const (
	commandAuth      commandName = "auth"
	commandParseAuth commandName = "parse-auth"
	commandProbe     commandName = "probe"
	commandServe     commandName = "serve"
)

type lookupEnvFunc func(string) (string, bool)

type optionalString struct {
	value   string
	present bool
}

func presentString(value string) optionalString {
	return optionalString{value: value, present: true}
}

type probePatch struct {
	Portal   optionalString
	HostID   optionalString
	SSOFile  optionalString
	DebugLog optionalString
}

type authPatch struct {
	Portal            optionalString
	HostID            optionalString
	Browser           optionalString
	BrowserPath       optionalString
	BrowserProfileDir optionalString
	Timeout           optionalString
	DebugLog          optionalString
}

type servePatch struct {
	Listen            optionalString
	Portal            optionalString
	Gateway           optionalString
	HostID            optionalString
	Browser           optionalString
	BrowserPath       optionalString
	BrowserProfileDir optionalString
	Timeout           optionalString
	DebugLog          optionalString
}

type fileConfig struct {
	LogLevel optionalString
	Probe    probePatch
	Auth     authPatch
	Serve    servePatch
}

type cliInvocation struct {
	command    commandName
	configPath optionalString
	noConfig   bool
	logLevel   optionalString
	arguments  []string
	probe      probePatch
	auth       authPatch
	serve      servePatch
}

type rawInvocation struct {
	command  commandName
	logLevel optionalString
	probe    probePatch
	auth     authPatch
	serve    servePatch
}

func defaultsFor(command commandName) rawInvocation {
	defaults := rawInvocation{
		command:  command,
		logLevel: presentString("error"),
	}

	switch command {
	case commandProbe:
		defaults.probe = probePatch{
			Portal:   presentString(""),
			HostID:   presentString("gp-socks"),
			SSOFile:  presentString(""),
			DebugLog: presentString(""),
		}
	case commandAuth:
		defaults.auth = authPatch{
			Portal:            presentString(""),
			HostID:            presentString("gp-socks"),
			Browser:           presentString("auto"),
			BrowserPath:       presentString(""),
			BrowserProfileDir: presentString(""),
			Timeout:           presentString("5m"),
			DebugLog:          presentString(""),
		}
	case commandServe:
		defaults.serve = servePatch{
			Listen:            presentString("127.0.0.1:1080"),
			Portal:            presentString(""),
			Gateway:           presentString(""),
			HostID:            presentString("gp-socks"),
			Browser:           presentString("auto"),
			BrowserPath:       presentString(""),
			BrowserProfileDir: presentString(""),
			Timeout:           presentString("5m"),
			DebugLog:          presentString(""),
		}
	case commandParseAuth:
	}

	return defaults
}
