package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], app.IO{LookupEnv: os.LookupEnv, LogWriter: os.Stderr, AutoConfig: true})
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, ioConfig app.IO) int {
	runner := app.NewRunner(ioConfig)
	return exitCode(runner.Run(ctx, args))
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, app.ErrUsage) {
		return 2
	}
	return 1
}
