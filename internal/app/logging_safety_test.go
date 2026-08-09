package app

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestAppLogger_preservesErrorChainButOmitsRawError_whenCommandFailureLogged(t *testing.T) {
	// Given
	canaries := map[string]string{
		"URL":      "URL_CANARY_41A9",
		"path":     "PATH_CANARY_52B8",
		"username": "USERNAME_CANARY_63C7",
		"cookie":   "COOKIE_CANARY_74D6",
		"bearer":   "BEARER_CANARY_85E5",
		"SAML":     "SAML_CANARY_96F4",
	}
	sentinel := errors.New(strings.Join([]string{
		"url=https://vpn.example.test/" + canaries["URL"],
		"path=/home/alice/" + canaries["path"],
		"username=" + canaries["username"],
		"cookie=" + canaries["cookie"],
		"bearer=Bearer " + canaries["bearer"],
		"saml=<SAMLResponse>" + canaries["SAML"] + "</SAMLResponse>",
	}, " "))
	rawError := fmt.Errorf("wrapped transport failure: %w", sentinel)
	var failure *commandFailure = fail(
		commandAuth,
		failureStage("browser_capture"),
		failureCode("authentication_failed"),
		rawError,
	)
	var output bytes.Buffer
	logger := newAppLogger(&output, mustParseLogLevel(t, "error"))

	// When
	logger.errorCommandFailed(failure)

	// Then
	if !errors.Is(failure, sentinel) {
		t.Fatalf("command failure = %v, want wrapped sentinel", failure)
	}
	assertLogRecords(t, decodeLogRecords(t, output.String()), []logRecord{{
		"level": "ERROR", "msg": "command failed", "command": "auth", "stage": "browser_capture", "code": "authentication_failed",
	}})
	for kind, canary := range canaries {
		if strings.Contains(output.String(), canary) {
			t.Fatalf("application log leaked %s canary %q: %q", kind, canary, output.String())
		}
	}
}

func TestFailureMetadata_preservesErrorIdentity_whenCauseWrapped(t *testing.T) {
	// Given
	sentinel := errors.New("original failure")

	// When
	err := withFailureMetadata(sentinel, failureMetadata{
		stage: failureStageConfig,
		code:  failureCodeConfigOpen,
	})

	// Then
	if !errors.Is(err, sentinel) {
		t.Fatalf("failure metadata error = %v, want wrapped sentinel", err)
	}
}

func TestAppLogger_keepsWritersAndThresholdsIsolated_whenMultipleRunsExist(t *testing.T) {
	// Given
	var firstOutput bytes.Buffer
	var secondOutput bytes.Buffer
	firstLogger := newAppLogger(&firstOutput, mustParseLogLevel(t, "debug"))
	secondLogger := newAppLogger(&secondOutput, mustParseLogLevel(t, "error"))
	var firstFailure *commandFailure = fail(commandAuth, failureStage("portal_prelogin"), failureCode("portal_unavailable"), errors.New("first private error"))
	var secondFailure *commandFailure = fail(commandServe, failureStage("gateway_login"), failureCode("gateway_unavailable"), errors.New("second private error"))

	// When
	firstLogger.debugCommandStarted(commandAuth)
	secondLogger.debugCommandStarted(commandServe)
	firstLogger.infoCommandCompleted(commandAuth)
	secondLogger.infoCommandCompleted(commandServe)
	firstLogger.warnGatewayFallback()
	secondLogger.warnGatewayFallback()
	firstLogger.errorCommandFailed(firstFailure)
	secondLogger.errorCommandFailed(secondFailure)

	// Then
	assertLogRecords(t, decodeLogRecords(t, firstOutput.String()), []logRecord{
		{"level": "DEBUG", "msg": "command started", "command": "auth"},
		{"level": "INFO", "msg": "command completed", "command": "auth"},
		{"level": "WARN", "msg": "gateway fallback"},
		{"level": "ERROR", "msg": "command failed", "command": "auth", "stage": "portal_prelogin", "code": "portal_unavailable"},
	})
	assertLogRecords(t, decodeLogRecords(t, secondOutput.String()), []logRecord{
		{"level": "ERROR", "msg": "command failed", "command": "serve", "stage": "gateway_login", "code": "gateway_unavailable"},
	})
}

func TestNewAppLogger_leavesSlogDefaultIdentityUnchanged_whenConstructedAndUsed(t *testing.T) {
	// Given
	before := slog.Default()
	var output bytes.Buffer

	// When
	logger := newAppLogger(&output, mustParseLogLevel(t, "info"))
	afterConstruction := slog.Default()
	logger.infoCommandCompleted(commandProbe)
	afterUse := slog.Default()

	// Then
	if afterConstruction != before {
		t.Fatal("newAppLogger changed slog.Default during construction")
	}
	if afterUse != before {
		t.Fatal("application logger changed slog.Default during use")
	}
}
