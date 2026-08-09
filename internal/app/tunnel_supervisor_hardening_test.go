package app

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTunnelSupervisorImmediateFailuresUseOneBudget(t *testing.T) {
	initialCause := errors.New("initial packet failure")
	replacementCause := errors.New("replacement packet failure")
	initial := newFakeHealthDialer()
	initial.fail(initialCause)
	var calls int
	var delays []time.Duration
	supervisor := newTunnelSupervisorWithOptions(context.Background(), initial,
		func(context.Context, context.Context) (healthDialer, error) {
			calls++
			failed := newFakeHealthDialer()
			failed.fail(replacementCause)
			return failed, nil
		}, supervisorOptions{
			attempts: 3,
			delay:    10 * time.Millisecond,
			timeout:  time.Second,
			wait: func(_ context.Context, delay time.Duration) bool {
				delays = append(delays, delay)
				return true
			},
		})
	defer supervisor.Close()
	waitSupervisorDone(t, supervisor)
	if calls != 3 {
		t.Fatalf("factory calls = %d, want 3", calls)
	}
	wantDelays := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}
	if len(delays) != len(wantDelays) {
		t.Fatalf("backoff delays = %v, want %v", delays, wantDelays)
	}
	for index := range wantDelays {
		if delays[index] != wantDelays[index] {
			t.Fatalf("backoff delays = %v, want %v", delays, wantDelays)
		}
	}
	if err := supervisor.Err(); !errors.Is(err, initialCause) {
		t.Fatalf("supervisor error = %v, want initial cause", err)
	}
	if err := supervisor.Err(); !errors.Is(err, replacementCause) {
		t.Fatalf("supervisor error = %v, want replacement cause", err)
	}
}

func TestTunnelSupervisorSeparatesConnectAndLifetimeContexts(t *testing.T) {
	initial := newFakeHealthDialer()
	initial.fail(errors.New("packet tunnel failed"))
	contexts := make(chan [2]context.Context, 1)
	replacement := newFakeHealthDialer()
	supervisor := newTunnelSupervisorWithOptions(context.Background(), initial,
		func(connectCtx, lifetimeCtx context.Context) (healthDialer, error) {
			contexts <- [2]context.Context{connectCtx, lifetimeCtx}
			return replacement, nil
		}, supervisorOptions{attempts: 1, timeout: time.Second})
	seen := <-contexts
	select {
	case <-seen[0].Done():
	case <-time.After(time.Second):
		t.Fatal("connect context was not canceled after factory returned")
	}
	select {
	case <-seen[1].Done():
		t.Fatal("lifetime context canceled with connect context")
	default:
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-seen[1].Done():
	case <-time.After(time.Second):
		t.Fatal("lifetime context was not canceled on supervisor close")
	}
}

func TestTunnelSupervisorSharedLifetimeTreatsCancellationAsClean(t *testing.T) {
	for range 100 {
		lifetimeCtx, cancelLifetime := context.WithCancel(context.Background())
		initial := newFakeHealthDialer()
		go func() {
			<-lifetimeCtx.Done()
			close(initial.done)
		}()
		supervisor := newTunnelSupervisorOnContext(
			lifetimeCtx, cancelLifetime, initial,
			func(context.Context, context.Context) (healthDialer, error) {
				return nil, errors.New("unexpected reconnect")
			},
			supervisorOptions{attempts: 1, timeout: time.Second},
		)
		cancelLifetime()
		waitSupervisorDone(t, supervisor)
		if err := supervisor.Err(); err != nil {
			t.Fatalf("supervisor error after lifetime cancellation = %v", err)
		}
	}
}

func TestTunnelSupervisorClosesDialerWithoutMutex(t *testing.T) {
	var supervisor *tunnelSupervisor
	dialer := newCallbackCloseDialer(func() { _ = supervisor.Err() })
	supervisor = newTunnelSupervisorWithOptions(context.Background(), dialer,
		func(context.Context, context.Context) (healthDialer, error) {
			return nil, errors.New("unused")
		}, supervisorOptions{attempts: 1, timeout: time.Second})
	closed := make(chan struct{})
	go func() {
		_ = supervisor.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close() held the supervisor mutex while closing the dialer")
	}
}

func TestTunnelSupervisorDialWaitsForGenerationChange(t *testing.T) {
	dialer := &waitingFailureDialer{
		done: make(chan struct{}),
		err:  errors.New("generation failed"),
	}
	supervisor := newTunnelSupervisorWithOptions(context.Background(), dialer,
		func(context.Context, context.Context) (healthDialer, error) {
			return nil, errors.New("unused")
		}, supervisorOptions{attempts: 1, timeout: time.Second})
	defer supervisor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := supervisor.DialContext(ctx, "tcp", "example.test:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext() error = %v, want deadline exceeded", err)
	}
	if calls := dialer.calls.Load(); calls != 1 {
		t.Fatalf("DialContext calls = %d, want 1", calls)
	}
}

func waitSupervisorDone(t *testing.T, supervisor *tunnelSupervisor) {
	t.Helper()
	select {
	case <-supervisor.Done():
	case <-time.After(time.Second):
		t.Fatal("supervisor did not finish")
	}
}

type callbackCloseDialer struct {
	done    chan struct{}
	onClose func()
	once    sync.Once
}

func newCallbackCloseDialer(onClose func()) *callbackCloseDialer {
	return &callbackCloseDialer{done: make(chan struct{}), onClose: onClose}
}

func (d *callbackCloseDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unused")
}

func (d *callbackCloseDialer) Done() <-chan struct{} { return d.done }
func (d *callbackCloseDialer) Err() error            { return nil }
func (d *callbackCloseDialer) Close() error {
	d.once.Do(d.onClose)
	return nil
}

type waitingFailureDialer struct {
	done  chan struct{}
	err   error
	calls atomic.Int32
}

func (d *waitingFailureDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, d.err
}

func (d *waitingFailureDialer) Done() <-chan struct{} { return d.done }
func (d *waitingFailureDialer) Err() error            { return d.err }
func (d *waitingFailureDialer) Close() error          { return nil }
