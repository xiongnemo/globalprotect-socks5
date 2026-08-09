package app

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

type logLevel slog.Level

func parseLogLevel(raw string) (logLevel, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "error":
		return logLevel(slog.LevelError), nil
	case "warn":
		return logLevel(slog.LevelWarn), nil
	case "info":
		return logLevel(slog.LevelInfo), nil
	case "debug":
		return logLevel(slog.LevelDebug), nil
	default:
		return 0, withFailureMetadata(fmt.Errorf("unsupported log level"), failureMetadata{
			stage: failureStageConfig,
			code:  failureCodeLogLevelInvalid,
		})
	}
}

type appLogger struct {
	logger *slog.Logger
}

func newAppLogger(writer io.Writer, level logLevel) *appLogger {
	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{
		Level: slog.Level(level),
		ReplaceAttr: func(_ []string, attribute slog.Attr) slog.Attr {
			if attribute.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attribute
		},
	})
	return &appLogger{logger: slog.New(handler)}
}

func newDefaultAppLogger(writer io.Writer) *appLogger {
	return newAppLogger(writer, logLevel(slog.LevelError))
}

func (logger *appLogger) debugCommandStarted(command commandName) {
	logger.logger.Debug("command started", slog.String("command", string(command)))
}

func (logger *appLogger) infoCommandCompleted(command commandName) {
	logger.logger.Info("command completed", slog.String("command", string(command)))
}

func (logger *appLogger) warnGatewayFallback() {
	logger.logger.Warn("gateway fallback")
}

func (logger *appLogger) errorCommandFailed(failure *commandFailure) {
	logger.logger.Error(
		"command failed",
		slog.String("command", string(failure.command)),
		slog.String("stage", string(failure.stage)),
		slog.String("code", string(failure.code)),
	)
}

type failureStage string

type failureCode string

const (
	failureStageArguments failureStage = "arguments"
	failureStageConfig    failureStage = "config"
	failureStageExecution failureStage = "execution"
	failureStageListener  failureStage = "listener"

	failureCodeInvalidArguments     failureCode = "invalid_arguments"
	failureCodeInvalidConfiguration failureCode = "invalid_configuration"
	failureCodeConfigOpen           failureCode = "config_open"
	failureCodeLogLevelInvalid      failureCode = "log_level_invalid"
	failureCodeCommandFailed        failureCode = "command_failed"
	failureCodeListenFailed         failureCode = "listen_failed"
)

type failureMetadata struct {
	stage failureStage
	code  failureCode
}

type failureMetadataError struct {
	metadata failureMetadata
	cause    error
}

func withFailureMetadata(cause error, metadata failureMetadata) error {
	return &failureMetadataError{metadata: metadata, cause: cause}
}

func (failure *failureMetadataError) Error() string {
	return failure.cause.Error()
}

func (failure *failureMetadataError) Unwrap() error {
	return failure.cause
}

func classifyFailure(command commandName, fallback failureMetadata, cause error) *commandFailure {
	metadata := fallback
	var metadataError *failureMetadataError
	if errors.As(cause, &metadataError) {
		metadata = metadataError.metadata
	}
	return fail(command, metadata.stage, metadata.code, cause)
}

type commandFailure struct {
	command commandName
	stage   failureStage
	code    failureCode
	cause   error
}

func fail(command commandName, stage failureStage, code failureCode, cause error) *commandFailure {
	return &commandFailure{
		command: command,
		stage:   stage,
		code:    code,
		cause:   cause,
	}
}

func (failure *commandFailure) Error() string {
	return "command failed"
}

func (failure *commandFailure) Unwrap() error {
	return failure.cause
}
