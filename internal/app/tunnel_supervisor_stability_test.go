package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTunnelSupervisorBoundsRapidPostPublishFailures(t *testing.T) {
	initial := newFakeHealthDialer()
	initial.fail(errors.New("initial failure"))
	candidates := make(chan *fakeHealthDialer, 3)
	var delays []time.Duration
	supervisor := newTunnelSupervisorWithOptions(context.Background(), initial,
		func(context.Context, context.Context) (healthDialer, error) {
			candidate := newFakeHealthDialer()
			candidates <- candidate
			return candidate, nil
		}, supervisorOptions{
			attempts: 3, delay: 10 * time.Millisecond, timeout: time.Second, stable: time.Hour,
			wait: func(_ context.Context, delay time.Duration) bool {
				delays = append(delays, delay)
				return true
			},
		})
	defer supervisor.Close()
	for attempt := 0; attempt < 3; attempt++ {
		candidate := <-candidates
		conn, err := supervisor.DialContext(context.Background(), "tcp", "example.test:443")
		if err != nil {
			t.Fatalf("DialContext() after replacement %d error = %v", attempt+1, err)
		}
		_ = conn.Close()
		candidate.fail(errors.New("rapid replacement failure"))
	}
	waitSupervisorDone(t, supervisor)
	select {
	case extra := <-candidates:
		t.Fatalf("factory exceeded reconnect budget with candidate %#v", extra)
	default:
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
}
