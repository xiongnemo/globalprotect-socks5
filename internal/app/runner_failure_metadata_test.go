package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
)

func Test_Run_emitsSpecificSafeFailureMetadata(t *testing.T) {
	// Given
	missingConfig := filepath.Join(t.TempDir(), "CONFIG_PATH_CANARY.yaml")
	tests := []struct {
		name      string
		args      []string
		command   string
		stage     string
		code      string
		forbidden []string
	}{
		{
			name:      "missing config",
			args:      []string{"--config", missingConfig, "parse-auth", testAuthArtifact},
			command:   "parse-auth",
			stage:     "config",
			code:      "config_open",
			forbidden: []string{missingConfig, "CONFIG_PATH_CANARY", "secret-token", "no such file"},
		},
		{
			name:      "unsupported log level",
			args:      []string{"--log-level", "LOG_LEVEL_CANARY", "parse-auth", testAuthArtifact},
			command:   "parse-auth",
			stage:     "config",
			code:      "log_level_invalid",
			forbidden: []string{"LOG_LEVEL_CANARY", "secret-token", "unsupported log level"},
		},
		{
			name:      "listen bind failure",
			args:      []string{"serve", "--listen", "LISTEN_ADDRESS_CANARY"},
			command:   "serve",
			stage:     "listener",
			code:      "listen_failed",
			forbidden: []string{"LISTEN_ADDRESS_CANARY", "missing port", "listen tcp"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var applicationLog bytes.Buffer
			runner := app.NewRunner(app.IO{
				Stdout:    io.Discard,
				Stderr:    io.Discard,
				LogWriter: &applicationLog,
				LookupEnv: func(string) (string, bool) { return "", false },
			})

			// When
			err := runner.Run(context.Background(), test.args)

			// Then
			if err == nil {
				t.Fatal("Run() error = nil, want failure")
			}
			var got map[string]string
			if decodeErr := json.Unmarshal(bytes.TrimSpace(applicationLog.Bytes()), &got); decodeErr != nil {
				t.Fatalf("decode application log %q: %v", applicationLog.String(), decodeErr)
			}
			want := map[string]string{
				"level":   "ERROR",
				"msg":     "command failed",
				"command": test.command,
				"stage":   test.stage,
				"code":    test.code,
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("application log record = %#v, want %#v", got, want)
			}
			for _, forbidden := range test.forbidden {
				if strings.Contains(applicationLog.String(), forbidden) {
					t.Errorf("application log leaked %q: %q", forbidden, applicationLog.String())
				}
			}
		})
	}
}
