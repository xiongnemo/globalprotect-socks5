package app_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
)

func Test_Run_printsRootFlagsInUsage_whenInvocationMissing(t *testing.T) {
	// Given
	var stderr bytes.Buffer
	runner := app.NewRunner(app.IO{
		Stdout:    io.Discard,
		Stderr:    &stderr,
		LogWriter: io.Discard,
		LookupEnv: func(string) (string, bool) { return "", false },
	})

	// When
	err := runner.Run(context.Background(), nil)

	// Then
	if !errors.Is(err, app.ErrUsage) {
		t.Fatalf("Run() error = %v, want ErrUsage", err)
	}
	want := "usage: gp-socks [--config FILE | --no-config] [--log-level LEVEL] <auth|parse-auth|probe|serve> [options]\n"
	if stderr.String() != want {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
}
