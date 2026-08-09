package app_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

const invalidListenerCanary = "PORTAL_CLEAR_LISTENER_CANARY"

func Test_Run_rejectsEmptyPortalOverride_whenFilePortalIsNonEmpty(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		lookupEnv func(string) (string, bool)
	}{
		{
			name: "present-empty environment",
			args: []string{"serve"},
			lookupEnv: func(name string) (string, bool) {
				if name == "GP_SOCKS_PORTAL" {
					return "", true
				}
				return "", false
			},
		},
		{
			name:      "present-empty CLI",
			args:      []string{"serve", "--portal="},
			lookupEnv: func(string) (string, bool) { return "", false },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			writeRunnerConfig(t, configPath, `serve:
  listen: "`+invalidListenerCanary+`"
  portal: "https://configured.example.test"
`)
			effects := &serveSideEffects{}
			runner := effects.runner(test.lookupEnv)
			args := append([]string{"--config", configPath}, test.args...)

			// When
			err := runner.Run(context.Background(), args)

			// Then
			if err == nil {
				t.Fatal("Run() error = nil, want portal-clearing configuration error")
			}
			if errors.Is(err, errUnexpectedServeSideEffect) {
				t.Errorf("Run() error = %v, reached a runtime collaborator", err)
			}
			if strings.Contains(err.Error(), invalidListenerCanary) {
				t.Errorf("Run() error = %v, reached direct listener after clearing configured portal", err)
			}
			if !strings.Contains(effects.applicationLog.String(), `"stage":"config"`) {
				t.Errorf("application log = %q, want configuration-stage failure", effects.applicationLog.String())
			}
			effects.assertCollaboratorsIdle(t)
		})
	}
}

func Test_Run_keepsPresentEmptyPortalAsDirectMode_whenNoLowerPortalExists(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		lookupEnv func(string) (string, bool)
	}{
		{
			name: "present-empty environment",
			args: []string{"serve"},
			lookupEnv: func(name string) (string, bool) {
				if name == "GP_SOCKS_PORTAL" {
					return "", true
				}
				return "", false
			},
		},
		{
			name:      "present-empty CLI",
			args:      []string{"serve", "--portal="},
			lookupEnv: func(string) (string, bool) { return "", false },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			writeRunnerConfig(t, configPath, "serve:\n  listen: \""+invalidListenerCanary+"\"\n")
			effects := &serveSideEffects{}
			runner := effects.runner(test.lookupEnv)
			args := append([]string{"--config", configPath}, test.args...)

			// When
			err := runner.Run(context.Background(), args)

			// Then
			if err == nil || !strings.Contains(err.Error(), invalidListenerCanary) {
				t.Fatalf("Run() error = %v, want direct listener attempt", err)
			}
			effects.assertCollaboratorsIdle(t)
		})
	}
}
