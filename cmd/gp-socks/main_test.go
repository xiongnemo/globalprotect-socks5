package main

import (
	"errors"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
)

func TestExitCode_mapsRunnerOutcome(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "success", err: nil, want: 0},
		{name: "usage", err: app.ErrUsage, want: 2},
		{name: "wrapped usage", err: errors.Join(errors.New("context"), app.ErrUsage), want: 2},
		{name: "failure", err: errors.New("failure"), want: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			got := exitCode(test.err)

			// Then
			if got != test.want {
				t.Fatalf("exitCode() = %d, want %d", got, test.want)
			}
		})
	}
}
