package app

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
)

func TestServeWithTunnelHealthStopsListenerAfterReconnectBudget(t *testing.T) {
	initialCause := errors.New("initial tunnel failure")
	reconnectCause := errors.New("replacement unavailable")
	initial := newFakeHealthDialer()
	initial.fail(initialCause)
	supervisor := newTunnelSupervisorWithOptions(context.Background(), initial,
		func(context.Context, context.Context) (healthDialer, error) {
			return nil, reconnectCause
		}, supervisorOptions{attempts: 1, timeout: time.Second})
	defer supervisor.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	server := socks5.NewServer(socks5.Config{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unexpected SOCKS dial")
		},
	})

	err = serveWithTunnelHealth(context.Background(), server, listener, supervisor)
	if !errors.Is(err, initialCause) || !errors.Is(err, reconnectCause) {
		t.Fatalf("serveWithTunnelHealth() error = %v, want both tunnel causes", err)
	}
	if !strings.Contains(err.Error(), "packet tunnel stopped") {
		t.Fatalf("serveWithTunnelHealth() error = %v, want terminal tunnel context", err)
	}
	if _, dialErr := net.DialTimeout("tcp", listener.Addr().String(), 50*time.Millisecond); dialErr == nil {
		t.Fatal("SOCKS listener remained reachable after reconnect budget exhaustion")
	}
}
