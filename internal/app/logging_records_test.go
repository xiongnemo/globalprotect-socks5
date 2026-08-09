package app

import (
	"bytes"
	"errors"
	"testing"
)

func TestAppLogger_filtersFixedSafeRecords_whenThresholdConfigured(t *testing.T) {
	allRecords := []logRecord{
		{"level": "DEBUG", "msg": "command started", "command": "serve"},
		{"level": "INFO", "msg": "command completed", "command": "serve"},
		{"level": "WARN", "msg": "gateway fallback"},
		{"level": "ERROR", "msg": "command failed", "command": "serve", "stage": "gateway_login", "code": "gateway_unavailable"},
	}
	tests := []struct {
		name      string
		threshold string
		want      []logRecord
	}{
		{name: "error includes only error", threshold: "error", want: allRecords[3:]},
		{name: "warn includes warn and error", threshold: "warn", want: allRecords[2:]},
		{name: "info includes info warn and error", threshold: "info", want: allRecords[1:]},
		{name: "debug includes every level", threshold: "debug", want: allRecords},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			var output bytes.Buffer
			logger := newAppLogger(&output, mustParseLogLevel(t, test.threshold))
			var failure *commandFailure = fail(
				commandServe,
				failureStage("gateway_login"),
				failureCode("gateway_unavailable"),
				errors.New("private raw failure"),
			)

			// When
			logger.debugCommandStarted(commandServe)
			logger.infoCommandCompleted(commandServe)
			logger.warnGatewayFallback()
			logger.errorCommandFailed(failure)

			// Then
			assertLogRecords(t, decodeLogRecords(t, output.String()), test.want)
		})
	}
}
