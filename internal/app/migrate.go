package app

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/xiongnemo/globalprotect-socks5/internal/userdirs"
)

type migrateOptions struct {
	from   string
	dryRun bool
}

const migrateHelp = `usage: gp-socks migrate [--dry-run] [--from FILE]

Moves the config.yaml that older versions read from the current directory (or
FILE) to $XDG_CONFIG_HOME/gp-socks/config.yaml, by default
~/.config/gp-socks/config.yaml. Relative paths in it (sso_file, debug_log,
browser_path, browser_profile_dir) were resolved from the directory gp-socks
ran in; they are rewritten as absolute paths under the file's old directory so
they keep pointing at the same files. An existing file at the new location is
never overwritten: an identical one makes the old copy redundant and it is
removed; a different one is a conflict, both are kept and migrate exits
non-zero. Running it again finds nothing to do.

migrate cannot tell whether gp-socks is running; stop it first.

`

func parseMigrateFlags(args []string, stderr io.Writer) (migrateOptions, error) {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dryRun := flags.Bool("dry-run", false, "print the plan and change nothing")
	from := flags.String("from", "", "configuration file to move (default ./config.yaml)")
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), migrateHelp)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return migrateOptions{}, fmt.Errorf("parse migrate flags: %w", err)
	}
	if flags.NArg() > 0 {
		return migrateOptions{}, fmt.Errorf("parse migrate flags: unexpected argument %q", flags.Arg(0))
	}
	return migrateOptions{from: *from, dryRun: *dryRun}, nil
}

// runMigrate needs no configuration, so it skips the file, environment and
// flag layers. Its plan goes to stdout and a hard error to stderr, both
// user-facing; the JSON log gets only the fixed failure classification.
func (r Runner) runMigrate(cli cliInvocation) error {
	if cli.configPath.present || cli.noConfig {
		err := errors.New("migrate takes --from FILE, not --config or --no-config")
		fmt.Fprintf(r.io.Stderr, "gp-socks migrate: %v\n", err)
		r.logFailure(fail(commandMigrate, failureStageArguments, failureCodeInvalidArguments, err))
		return err
	}
	err := r.userDirs().Migrate(userdirs.MigrateOptions{
		From:    cli.migrate.from,
		DryRun:  cli.migrate.dryRun,
		Rewrite: rewriteConfigPaths,
		Out:     r.io.Stdout,
	})
	if err != nil {
		if !errors.Is(err, userdirs.ErrConflict) {
			fmt.Fprintf(r.io.Stderr, "gp-socks migrate: %v\n", err)
		}
		r.logFailure(fail(commandMigrate, failureStageExecution, failureCodeCommandFailed, err))
	}
	return err
}

// configPathKeys are the settings that hold file system paths, by section.
var configPathKeys = []struct{ section, key string }{
	{"probe", "sso_file"}, {"probe", "debug_log"},
	{"auth", "browser_path"}, {"auth", "browser_profile_dir"}, {"auth", "debug_log"},
	{"serve", "browser_path"}, {"serve", "browser_profile_dir"}, {"serve", "debug_log"},
}

// rewriteConfigPaths returns the configuration with each relative path
// setting made absolute against dir, keeping comments and every other node.
// gp-socks resolves relative paths from its working directory, which for the
// automatic ./config.yaml was the file's own directory.
func rewriteConfigPaths(data []byte, dir string) ([]byte, []userdirs.PathRewrite, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return data, nil, fmt.Errorf("decode YAML document: %w", err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return data, nil, errors.New("config must be one YAML mapping")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return data, nil, err
	}
	var rewrites []userdirs.PathRewrite
	for _, field := range configPathKeys {
		node := mappingValue(mappingValue(document.Content[0], field.section), field.key)
		if node == nil || node.Kind != yaml.ScalarNode || !isRelativePath(node.Value) {
			continue
		}
		rewrites = append(rewrites, userdirs.PathRewrite{Key: field.section + "." + field.key, Old: node.Value, New: filepath.Join(absDir, node.Value)})
		node.Value = filepath.Join(absDir, node.Value)
	}
	if len(rewrites) == 0 {
		return data, nil, nil
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return data, nil, err
	}
	if err := encoder.Close(); err != nil {
		return data, nil, err
	}
	return out.Bytes(), rewrites, nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

// isRelativePath reports a non-blank path that depends on the working
// directory. Rooted Windows paths (\x, C:x) and values with surrounding spaces
// are left alone rather than guessed at.
func isRelativePath(path string) bool {
	if strings.TrimSpace(path) != path || path == "" {
		return false
	}
	if filepath.IsAbs(path) || filepath.VolumeName(path) != "" {
		return false
	}
	return !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, string(filepath.Separator))
}
