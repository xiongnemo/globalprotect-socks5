package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	defaultReconnectAttempts = 5
	defaultReconnectDelay    = time.Second
	defaultReconnectTimeout  = 30 * time.Second
	defaultReconnectStable   = 30 * time.Second
)

type healthDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	Done() <-chan struct{}
	Err() error
	Close() error
}

type healthDialerFactory func(connectCtx context.Context, lifetimeCtx context.Context) (healthDialer, error)

type supervisorOptions struct {
	attempts int
	delay    time.Duration
	timeout  time.Duration
	stable   time.Duration
	wait     func(context.Context, time.Duration) bool
}

type tunnelSupervisor struct {
	ctx     context.Context
	cancel  context.CancelFunc
	factory healthDialerFactory
	options supervisorOptions

	mu      sync.Mutex
	current healthDialer
	changed chan struct{}
	err     error
	closed  bool
	done    chan struct{}
	wg      sync.WaitGroup
}

func newTunnelSupervisorWithOptions(ctx context.Context, initial healthDialer, factory healthDialerFactory, options supervisorOptions) *tunnelSupervisor {
	runCtx, cancel := context.WithCancel(ctx)
	return newTunnelSupervisorOnContext(runCtx, cancel, initial, factory, options)
}

func newTunnelSupervisorOnContext(
	runCtx context.Context,
	cancel context.CancelFunc,
	initial healthDialer,
	factory healthDialerFactory,
	options supervisorOptions,
) *tunnelSupervisor {
	if options.attempts < 1 {
		options.attempts = 1
	}
	if options.delay < 0 {
		options.delay = 0
	}
	if options.timeout <= 0 {
		options.timeout = defaultReconnectTimeout
	}
	if options.stable <= 0 {
		options.stable = defaultReconnectStable
	}
	if options.wait == nil {
		options.wait = waitContext
	}
	s := &tunnelSupervisor{
		ctx: runCtx, cancel: cancel, factory: factory, options: options,
		current: initial, changed: make(chan struct{}), done: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s
}

func (s *tunnelSupervisor) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	for {
		s.mu.Lock()
		current, changed, terminal, closed := s.current, s.changed, s.err, s.closed
		s.mu.Unlock()
		if terminal != nil {
			return nil, terminal
		}
		if closed {
			return nil, net.ErrClosed
		}
		if current == nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		conn, err := current.DialContext(ctx, network, address)
		if err != nil && current.Err() != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		return conn, err
	}
}

func (s *tunnelSupervisor) Done() <-chan struct{} { return s.done }

func (s *tunnelSupervisor) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *tunnelSupervisor) Close() error {
	s.cancel()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *tunnelSupervisor) run() {
	defer s.wg.Done()
	connectedAt := time.Now()
	attemptsUsed := 0
	var failures []error
	for {
		s.mu.Lock()
		current := s.current
		s.mu.Unlock()
		select {
		case <-s.ctx.Done():
			s.finish(nil)
			return
		case <-current.Done():
			if s.ctx.Err() != nil {
				s.finish(nil)
				return
			}
			cause := current.Err()
			s.setCurrent(nil)
			_ = current.Close()
			if cause == nil {
				s.finish(errors.New("tunnel closed unexpectedly"))
				return
			}
			if time.Since(connectedAt) >= s.options.stable {
				attemptsUsed = 0
				failures = nil
			}
			failures = append(failures, fmt.Errorf("packet tunnel failed: %w", cause))
			next, used, reconnectFailures, err := s.reconnect(attemptsUsed, failures)
			if err != nil {
				s.finish(fmt.Errorf("reconnect packet tunnel: %w", err))
				return
			}
			attemptsUsed = used
			failures = reconnectFailures
			connectedAt = time.Now()
			s.setCurrent(next)
		}
	}
}

func (s *tunnelSupervisor) setCurrent(current healthDialer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = current
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *tunnelSupervisor) finish(err error) {
	s.mu.Lock()
	current := s.current
	s.current = nil
	if err != nil && !errors.Is(err, context.Canceled) {
		s.err = err
	}
	s.closed = true
	close(s.changed)
	close(s.done)
	s.mu.Unlock()
	if current != nil {
		_ = current.Close()
	}
}
