// Package userdirs places gp-socks' per-user files in the XDG Base Directory
// layout, the same on Linux, macOS and Windows, and finds the config.yaml that
// older versions read from the working directory.
//
// gp-socks keeps one per-user file: config.yaml. Its browser profile is a
// temporary directory removed after each authentication unless the user names
// a persistent one, and its debug log and SSO file are written only where the
// user asks, so none of those has a default location to manage.
package userdirs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Tool is the command name, and the directory name under each XDG base.
const Tool = "gp-socks"

// ConfigName is the configuration file name, in the XDG directory and in the
// working directory where versions before the XDG layout looked for it.
const ConfigName = "config.yaml"

// ErrNoHome means neither an absolute XDG_CONFIG_HOME nor a home directory is
// known, so the XDG location cannot be computed.
var ErrNoHome = errors.New("no home directory")

// Env is the part of the process environment the resolver reads, injected so
// that an embedding program, or a test, decides what it sees. A nil LookupEnv
// sees no variables; a nil HomeDir knows no home; a nil WorkDir is os.Getwd.
type Env struct {
	LookupEnv func(string) (string, bool)
	HomeDir   func() (string, error)
	WorkDir   func() (string, error)
}

// ConfigHome is $XDG_CONFIG_HOME, or ~/.config when that is unset or not an
// absolute path (the XDG spec says relative values are invalid). ~ is
// os.UserHomeDir: $HOME on Unix, %USERPROFILE% on Windows.
func (e Env) ConfigHome() (string, error) {
	if e.LookupEnv != nil {
		if dir, _ := e.LookupEnv("XDG_CONFIG_HOME"); dir != "" && filepath.IsAbs(dir) {
			return filepath.Clean(dir), nil
		}
	}
	if e.HomeDir == nil {
		return "", ErrNoHome
	}
	home, err := e.HomeDir()
	if err == nil && home == "" {
		err = errors.New("home directory is empty")
	}
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoHome, err)
	}
	return filepath.Join(home, ".config"), nil
}

// ConfigFile is $XDG_CONFIG_HOME/gp-socks/config.yaml.
func (e Env) ConfigFile() (string, error) {
	base, err := e.ConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, Tool, ConfigName), nil
}

func (e Env) workDir() (string, error) {
	getwd := e.WorkDir
	if getwd == nil {
		getwd = os.Getwd
	}
	wd, err := getwd()
	if err != nil {
		return "", fmt.Errorf("locate the working directory: %w", err)
	}
	return wd, nil
}

// LegacyConfigFile is config.yaml in the working directory, the automatic
// configuration of every release before the XDG layout.
func (e Env) LegacyConfigFile() (string, error) {
	wd, err := e.workDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(wd, ConfigName), nil
}

// ConfigChoice is the automatic configuration file a run uses. The file is
// optional: if it does not exist, the run goes on without one.
type ConfigChoice struct {
	// Path is the file to load if it exists.
	Path string
	// Legacy reports that Path is the old working-directory file and New is
	// known; the caller tells the user once, on stderr.
	Legacy bool
	// New is the XDG location, or "" when no home directory is known.
	New string
}

// ResolveConfig picks the automatic configuration file: the XDG file if it
// exists, else ./config.yaml if that exists, else the XDG path. Without a home
// directory there is no XDG path, and ./config.yaml is used as before.
func (e Env) ResolveConfig() (ConfigChoice, error) {
	legacy, err := e.LegacyConfigFile()
	if err != nil {
		return ConfigChoice{}, err
	}
	newPath, err := e.ConfigFile()
	if errors.Is(err, ErrNoHome) {
		return ConfigChoice{Path: legacy}, nil
	}
	if err != nil {
		return ConfigChoice{}, err
	}
	if fileExists(newPath) {
		return ConfigChoice{Path: newPath, New: newPath}, nil
	}
	if fileExists(legacy) {
		return ConfigChoice{Path: legacy, Legacy: true, New: newPath}, nil
	}
	return ConfigChoice{Path: newPath, New: newPath}, nil
}

// LegacyNotice is the one line printed to stderr when a run falls back to the
// old location.
func (c ConfigChoice) LegacyNotice() string {
	return fmt.Sprintf("%s: using the configuration from the old location %s; run \"%s migrate\" to move it to %s", Tool, c.Path, Tool, c.New)
}

// fileExists reports whether path names something other than a directory. A
// file that exists but cannot be inspected counts, so loading it reports the
// real error instead of silently falling through to another file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	return !info.IsDir()
}
