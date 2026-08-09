package app

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTunnelSupervisorReconnectsAndUnblocksDial(t *testing.T) {
	cause := errors.New("packet tunnel failed")
	initial := newFakeHealthDialer()
	initial.fail(cause)
	replacement := newFakeHealthDialer()
	factoryCalls := 0
	factory := func(context.Context, context.Context) (healthDialer, error) {
		factoryCalls++
		if factoryCalls == 1 {
			return nil, errors.New("temporary reconnect failure")
		}
		return replacement, nil
	}
	supervisor := newTunnelSupervisorWithOptions(context.Background(), initial, factory, supervisorOptions{
		attempts: 2, delay: time.Millisecond, timeout: time.Second,
	})
	defer supervisor.Close()
	conn, err := supervisor.DialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	_ = conn.Close()
	if factoryCalls != 2 {
		t.Fatalf("factory calls = %d, want 2", factoryCalls)
	}
}

func TestTunnelSupervisorStopsAfterReconnectBudget(t *testing.T) {
	initial := newFakeHealthDialer()
	initial.fail(errors.New("packet tunnel failed"))
	supervisor := newTunnelSupervisorWithOptions(context.Background(), initial, func(context.Context, context.Context) (healthDialer, error) {
		return nil, errors.New("still unavailable")
	}, supervisorOptions{attempts: 2, delay: time.Millisecond, timeout: time.Second})
	defer supervisor.Close()
	select {
	case <-supervisor.Done():
	case <-time.After(time.Second):
		t.Fatal("supervisor did not exhaust reconnect budget")
	}
	if supervisor.Err() == nil {
		t.Fatal("supervisor error = nil")
	}
}

func TestTunnelSupervisorCloseCancelsReconnectBackoff(t *testing.T) {
	initial := newFakeHealthDialer()
	initial.fail(errors.New("packet tunnel failed"))
	supervisor := newTunnelSupervisorWithOptions(context.Background(), initial, func(context.Context, context.Context) (healthDialer, error) {
		return nil, errors.New("unavailable")
	}, supervisorOptions{attempts: 5, delay: time.Hour, timeout: time.Second})
	closed := make(chan struct{})
	go func() {
		_ = supervisor.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close() did not cancel reconnect backoff")
	}
}

func TestTunnelSupervisorDialAfterCloseReturnsNetErrClosed(t *testing.T) {
	supervisor := newTunnelSupervisorWithOptions(context.Background(), newFakeHealthDialer(), func(context.Context, context.Context) (healthDialer, error) {
		return nil, errors.New("unused")
	}, supervisorOptions{attempts: 1, timeout: time.Second})
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_, err := supervisor.DialContext(context.Background(), "tcp", "example.test:443")
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("DialContext() error = %v, want net.ErrClosed", err)
	}
}

type fakeHealthDialer struct {
	mu   sync.Mutex
	done chan struct{}
	err  error
}

func newFakeHealthDialer() *fakeHealthDialer {
	return &fakeHealthDialer{done: make(chan struct{})}
}

func (d *fakeHealthDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	if err := d.Err(); err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (d *fakeHealthDialer) Done() <-chan struct{} { return d.done }

func (d *fakeHealthDialer) Err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

func (d *fakeHealthDialer) Close() error { return nil }

func (d *fakeHealthDialer) fail(err error) {
	d.mu.Lock()
	d.err = err
	d.mu.Unlock()
	close(d.done)
}
