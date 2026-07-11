package app

import (
	"context"
	"flag"
	"fmt"
	"net"

	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
)

func (r Runner) serve(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(r.io.Stderr)
	listenAddr := flags.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse serve flags: %w", err)
	}
	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listenAddr, err)
	}
	defer listener.Close()
	if _, err := fmt.Fprintf(r.io.Stdout, "listening=%s\n", listener.Addr().String()); err != nil {
		return fmt.Errorf("write listen summary: %w", err)
	}
	server := socks5.NewServer(socks5.Config{DialContext: r.io.DialContext})
	return server.Serve(ctx, listener)
}

func dialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}
