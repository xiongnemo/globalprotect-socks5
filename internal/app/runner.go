package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
)

var ErrUsage = errors.New("app: usage")

const defaultHTTPTimeout = 30 * time.Second

type IO struct {
	Stdout                io.Writer
	Stderr                io.Writer
	LogWriter             io.Writer
	LookupEnv             func(string) (string, bool)
	AutoConfig            bool
	HTTPClient            *http.Client
	AuthCapturer          AuthCapturer
	DialContext           socks5.DialFunc
	PacketTunnelConnector PacketTunnelConnector
}

type Runner struct {
	io IO
}

func NewRunner(ioConfig IO) Runner {
	if ioConfig.Stdout == nil {
		ioConfig.Stdout = os.Stdout
	}
	if ioConfig.Stderr == nil {
		ioConfig.Stderr = os.Stderr
	}
	if ioConfig.LogWriter == nil {
		ioConfig.LogWriter = ioConfig.Stderr
	}
	if ioConfig.LookupEnv == nil {
		ioConfig.LookupEnv = func(string) (string, bool) { return "", false }
	}
	if ioConfig.HTTPClient == nil {
		ioConfig.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if ioConfig.DialContext == nil {
		ioConfig.DialContext = dialContext
	}
	return Runner{io: ioConfig}
}

func (r Runner) Run(ctx context.Context, args []string) error {
	cli, err := parseCLIInvocation(args, r.io.Stderr)
	if err != nil {
		if errors.Is(err, ErrUsage) {
			return r.usage()
		}
		if cli.command != "" {
			r.logFailure(fail(cli.command, failureStageArguments, failureCodeInvalidArguments, err))
		}
		return err
	}

	prepared, err := r.prepareInvocation(cli)
	if err != nil {
		r.logFailure(classifyFailure(cli.command, failureMetadata{
			stage: failureStageConfig,
			code:  failureCodeInvalidConfiguration,
		}, err))
		return err
	}
	logger := newAppLogger(r.io.LogWriter, prepared.logLevel)
	logger.debugCommandStarted(prepared.command)

	switch prepared.command {
	case commandAuth:
		err = r.auth(ctx, prepared.auth)
	case commandParseAuth:
		err = r.parseAuth(prepared.arguments)
	case commandProbe:
		err = r.probe(ctx, prepared.probe)
	case commandServe:
		err = r.serve(ctx, prepared.serve, logger)
	}
	if err != nil {
		if !errors.Is(err, ErrUsage) {
			logger.errorCommandFailed(classifyFailure(prepared.command, failureMetadata{
				stage: failureStageExecution,
				code:  failureCodeCommandFailed,
			}, err))
		}
		return err
	}
	logger.infoCommandCompleted(prepared.command)
	return nil
}

func (r Runner) logFailure(failure *commandFailure) {
	logger := newDefaultAppLogger(r.io.LogWriter)
	logger.errorCommandFailed(failure)
}

func (r Runner) parseAuth(args []string) error {
	if len(args) != 1 {
		return r.usage()
	}
	artifact, err := gp.ParseAuthArtifact(args[0])
	if err != nil {
		return fmt.Errorf("parse auth artifact: %w", err)
	}
	return r.writeAuthSummary(artifact)
}

func (r Runner) usage() error {
	_, err := fmt.Fprintln(r.io.Stderr, "usage: gp-socks [--config FILE | --no-config] [--log-level LEVEL] <auth|parse-auth|probe|serve> [options]")
	if err != nil {
		return fmt.Errorf("write usage: %w", err)
	}
	return ErrUsage
}
