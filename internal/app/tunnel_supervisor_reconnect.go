package app

import (
	"context"
	"errors"
	"fmt"
	"time"
)

func (s *tunnelSupervisor) reconnect(attemptsUsed int, failures []error) (healthDialer, int, []error, error) {
	for attemptsUsed < s.options.attempts {
		if attemptsUsed > 0 && !s.options.wait(s.ctx, reconnectDelay(s.options.delay, attemptsUsed)) {
			return nil, attemptsUsed, failures, s.ctx.Err()
		}
		attemptCtx, cancel := context.WithTimeout(s.ctx, s.options.timeout)
		dialer, err := s.factory(attemptCtx, s.ctx)
		cancel()
		attemptsUsed++
		if err == nil && dialer == nil {
			err = errors.New("replacement tunnel factory returned nil")
		}
		if err == nil {
			if terminal, failed := terminalDialerError(dialer); failed {
				_ = dialer.Close()
				failures = append(failures, fmt.Errorf("replacement tunnel failed: %w", terminal))
				continue
			}
			return dialer, attemptsUsed, failures, nil
		}
		if s.ctx.Err() != nil {
			return nil, attemptsUsed, failures, s.ctx.Err()
		}
		failures = append(failures, err)
	}
	return nil, attemptsUsed, failures, errors.Join(failures...)
}

func terminalDialerError(dialer healthDialer) (error, bool) {
	select {
	case <-dialer.Done():
		if err := dialer.Err(); err != nil {
			return err, true
		}
		return errors.New("replacement tunnel closed unexpectedly"), true
	default:
		if err := dialer.Err(); err != nil {
			return err, true
		}
		return nil, false
	}
}

func reconnectDelay(base time.Duration, attempt int) time.Duration {
	return base * time.Duration(1<<(attempt-1))
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
