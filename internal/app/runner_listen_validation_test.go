package app_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func Test_Run_rejectsBlankFinalServeListen_beforeSideEffects(t *testing.T) {
	tests := []struct {
		name   string
		source string
		listen string
	}{
		{name: "YAML empty", source: "yaml", listen: ""},
		{name: "YAML whitespace", source: "yaml", listen: " \t "},
		{name: "environment empty", source: "environment", listen: ""},
		{name: "environment whitespace", source: "environment", listen: " \t "},
		{name: "CLI empty", source: "cli", listen: ""},
		{name: "CLI whitespace", source: "cli", listen: " \t "},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			effects := &serveSideEffects{}
			lookupEnv := func(string) (string, bool) { return "", false }
			args := []string{"serve", "--portal", "https://portal.example.test"}
			switch test.source {
			case "yaml":
				configPath := filepath.Join(t.TempDir(), "config.yaml")
				writeRunnerConfig(t, configPath, fmt.Sprintf("serve:\n  listen: %q\n", test.listen))
				args = append([]string{"--config", configPath}, args...)
			case "environment":
				lookupEnv = func(name string) (string, bool) {
					if name == "GP_SOCKS_LISTEN" {
						return test.listen, true
					}
					return "", false
				}
			case "cli":
				args = append(args, "--listen", test.listen)
			}
			runner := effects.runner(lookupEnv)

			// When
			err := runner.Run(context.Background(), args)

			// Then
			if err == nil {
				t.Fatal("Run() error = nil, want blank listen configuration error")
			}
			if errors.Is(err, errUnexpectedServeSideEffect) {
				t.Errorf("Run() error = %v, reached a runtime collaborator before listen validation", err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "listen") {
				t.Errorf("Run() error = %v, want listen configuration error", err)
			}
			effects.assertCollaboratorsIdle(t)
		})
	}
}

func Test_Run_rejectsUnsafeNonLoopbackListen_beforeSideEffects(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing explicit opt-in",
			args: []string{
				"serve", "--portal", "https://portal.example.test", "--listen", "0.0.0.0:1080",
			},
		},
		{
			name: "missing authentication",
			args: []string{
				"serve", "--portal", "https://portal.example.test", "--listen", "0.0.0.0:1080",
				"--allow-non-loopback",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			effects := &serveSideEffects{}
			runner := effects.runner(func(string) (string, bool) { return "", false })
			err := runner.Run(context.Background(), test.args)
			if err == nil {
				t.Fatal("Run() error = nil, want non-loopback policy rejection")
			}
			if errors.Is(err, errUnexpectedServeSideEffect) {
				t.Error("Run() reached a runtime collaborator before listen policy validation")
			}
			effects.assertCollaboratorsIdle(t)
		})
	}
}
