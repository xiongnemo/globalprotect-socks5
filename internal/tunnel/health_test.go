package tunnel_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

func Test_Dialer_DoneReportsPacketReadFailure(t *testing.T) {
	readErr := errors.New("read failed")
	packetTunnel := &healthTestTunnel{readErr: readErr, readStarted: make(chan struct{})}
	dialer, err := tunnel.NewDialer(context.Background(), healthConfig(packetTunnel))
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	t.Cleanup(func() { _ = dialer.Close() })

	waitHealthDone(t, packetTunnel.readStarted)
	waitHealthDone(t, dialer.Done())

	if !errors.Is(dialer.Err(), readErr) {
		t.Fatalf("Err() = %v, want read failure", dialer.Err())
	}
	select {
	case <-dialer.Done():
	default:
		t.Fatal("Done() reopened after terminal failure")
	}
}

func Test_Dialer_DoneClosesWithoutErrorWhenParentContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	packetTunnel := &healthTestTunnel{readStarted: make(chan struct{})}
	dialer, err := tunnel.NewDialer(ctx, healthConfig(packetTunnel))
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	waitHealthDone(t, packetTunnel.readStarted)

	cancel()
	waitHealthDone(t, dialer.Done())

	if err := dialer.Err(); err != nil {
		t.Fatalf("Err() = %v, want nil after context cancellation", err)
	}
}

func Test_Dialer_CloseIsIdempotentAndPreservesCloseError(t *testing.T) {
	closeErr := errors.New("close failed")
	packetTunnel := &healthTestTunnel{closeErr: closeErr, readStarted: make(chan struct{})}
	dialer, err := tunnel.NewDialer(context.Background(), healthConfig(packetTunnel))
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	waitHealthDone(t, packetTunnel.readStarted)

	const callers = 8
	start := make(chan struct{})
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- dialer.Close()
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var first error
	for err := range results {
		if !errors.Is(err, closeErr) {
			t.Fatalf("Close() error = %v, want close failure", err)
		}
		if first == nil {
			first = err
		} else if err != first {
			t.Fatalf("Close() returned different error instances: %v and %v", first, err)
		}
	}
	if got := packetTunnel.closeCalls(); got != 1 {
		t.Fatalf("packet tunnel Close() calls = %d, want 1", got)
	}
	waitHealthDone(t, dialer.Done())
	if err := dialer.Err(); err != nil {
		t.Fatalf("Err() = %v, want nil after explicit Close", err)
	}
	if err := dialer.Close(); err != first {
		t.Fatalf("later Close() error = %v, want same error %v", err, first)
	}
}

func Test_Dialer_CloseAndPacketFailureCanRace(t *testing.T) {
	for range 20 {
		readErr := errors.New("read failed")
		packetTunnel := &healthTestTunnel{
			readErr: readErr, readStarted: make(chan struct{}), releaseRead: make(chan struct{}),
		}
		dialer, err := tunnel.NewDialer(context.Background(), healthConfig(packetTunnel))
		if err != nil {
			t.Fatalf("NewDialer() error = %v", err)
		}
		waitHealthDone(t, packetTunnel.readStarted)

		closeDone := make(chan error, 1)
		go func() { closeDone <- dialer.Close() }()
		close(packetTunnel.releaseRead)
		if err := <-closeDone; err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		waitHealthDone(t, dialer.Done())
		if err := dialer.Err(); err != nil && !errors.Is(err, readErr) {
			t.Fatalf("Err() = %v, want nil or read failure", err)
		}
	}
}

type healthTestTunnel struct {
	readErr     error
	closeErr    error
	readStarted chan struct{}
	releaseRead chan struct{}
	startOnce   sync.Once
	mu          sync.Mutex
	closes      int
}

func (t *healthTestTunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	t.startOnce.Do(func() { close(t.readStarted) })
	if t.releaseRead != nil {
		select {
		case <-t.releaseRead:
			return nil, t.readErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if t.readErr != nil {
		return nil, t.readErr
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*healthTestTunnel) WritePacket(context.Context, []byte) error { return nil }

func (t *healthTestTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closes++
	return t.closeErr
}

func (t *healthTestTunnel) closeCalls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closes
}

func healthConfig(packetTunnel tunnel.PacketTunnel) tunnel.Config {
	return tunnel.Config{Tunnel: packetTunnel, LocalAddr: netip.MustParseAddr("10.0.0.2")}
}

func waitHealthDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for terminal state")
	}
}

var _ tunnel.PacketTunnel = (*healthTestTunnel)(nil)
