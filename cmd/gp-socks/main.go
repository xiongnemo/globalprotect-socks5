package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runner := app.NewRunner(app.IO{})
	if err := runner.Run(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, app.ErrUsage) {
			os.Exit(2)
		}
		slog.Error("fatal", slog.Any("err", err))
		os.Exit(1)
	}
}
