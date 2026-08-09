package tunnel_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

func Test_Dialer_DialContext_failsPromptly_afterPacketReadFails(t *testing.T) {
	// Given
	readErr := errors.New("read pump failed")
	packetTunnel := &failingReadTunnel{err: readErr, ready: make(chan struct{})}
	dialer, err := tunnel.NewDialer(testContext(t), tunnel.Config{Tunnel: packetTunnel, LocalAddr: netip.MustParseAddr("10.0.0.2")})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()
	waitClosed(t, packetTunnel.ready)

	// When
	_, err = dialer.DialContext(testContext(t), "tcp", "10.0.0.1:443")

	// Then
	if !errors.Is(err, readErr) {
		t.Fatalf("error = %v, want read pump error", err)
	}
	waitHealthDone(t, dialer.Done())
	if !errors.Is(dialer.Err(), readErr) {
		t.Fatalf("Err() = %v, want read pump error", dialer.Err())
	}
}

func Test_Dialer_DialContext_failsPromptly_afterPacketWriteFails(t *testing.T) {
	// Given
	writeErr := errors.New("write pump failed")
	packetTunnel := &failingWriteTunnel{err: writeErr}
	dialer, err := tunnel.NewDialer(testContext(t), tunnel.Config{Tunnel: packetTunnel, LocalAddr: netip.MustParseAddr("10.0.0.2")})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()

	// When
	_, err = dialer.DialContext(testContext(t), "tcp", "10.0.0.1:443")

	// Then
	if !errors.Is(err, writeErr) {
		t.Fatalf("error = %v, want write pump error", err)
	}
	waitHealthDone(t, dialer.Done())
	if !errors.Is(dialer.Err(), writeErr) {
		t.Fatalf("Err() = %v, want write pump error", dialer.Err())
	}
}

type failingReadTunnel struct {
	err   error
	ready chan struct{}
}

func (t *failingReadTunnel) ReadPacket(context.Context) ([]byte, error) {
	close(t.ready)
	return nil, t.err
}

func (t *failingReadTunnel) WritePacket(context.Context, []byte) error {
	return nil
}

func (t *failingReadTunnel) Close() error {
	return nil
}

type failingWriteTunnel struct {
	err error
}

func (t *failingWriteTunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *failingWriteTunnel) WritePacket(context.Context, []byte) error {
	return t.err
}

func (t *failingWriteTunnel) Close() error {
	return nil
}

func waitClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("packet tunnel read was not called")
	}
}

var _ tunnel.PacketTunnel = (*failingReadTunnel)(nil)
var _ tunnel.PacketTunnel = (*failingWriteTunnel)(nil)
