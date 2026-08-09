package gp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

func (t *SSLPacketTunnel) monitor() {
	defer t.wg.Done()
	interval := t.options.dpdInterval / 2
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			t.stop(nil)
			return
		case now := <-ticker.C:
			if t.options.rekeyAfter > 0 && now.Sub(t.started) >= t.options.rekeyAfter {
				t.stop(ErrGPSTRekeyDue)
				return
			}
			if t.deadPeer(now) {
				t.stop(ErrGPSTDeadPeer)
				return
			}
			if t.shouldSendDPD(now) {
				if err := t.writeDPD(t.ctx); err != nil {
					if t.ctx.Err() != nil {
						t.stop(nil)
						return
					}
					t.stop(fmt.Errorf("write gpst dpd: %w", err))
					return
				}
			}
		}
	}
}

func (t *SSLPacketTunnel) writeFrame(ctx context.Context, frame []byte) error {
	return t.writeFrameBefore(ctx, frame, nil)
}

func (t *SSLPacketTunnel) writeDPD(ctx context.Context) error {
	return t.writeFrameBefore(ctx, gpstDPDFrame(), t.markDPDSent)
}

func (t *SSLPacketTunnel) writeFrameBefore(ctx context.Context, frame []byte, beforeWrite func(time.Time)) error {
	if terminal := t.terminalError(); terminal != nil {
		return terminal
	}
	writeCtx, cancel := context.WithTimeout(ctx, t.options.writeTimeout)
	defer cancel()
	select {
	case <-writeCtx.Done():
		return writeCtx.Err()
	case <-t.writeLock:
	}
	defer func() { t.writeLock <- struct{}{} }()
	if stopped := t.stoppedError(ctx); stopped != nil {
		return stopped
	}
	if beforeWrite != nil {
		beforeWrite(time.Now())
	}
	if err := writeAllContext(writeCtx, t.conn, frame); err != nil {
		if stopped := t.stoppedError(ctx); stopped != nil {
			return stopped
		}
		return err
	}
	t.stateMu.Lock()
	t.lastTx = time.Now()
	t.stateMu.Unlock()
	return nil
}

func (t *SSLPacketTunnel) shouldSendDPD(now time.Time) bool {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	return t.dpdSent.IsZero() && now.Sub(t.lastRx) >= t.options.dpdInterval
}

func (t *SSLPacketTunnel) markDPDSent(now time.Time) {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	t.dpdSent = now
}

func (t *SSLPacketTunnel) markReceived() {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	t.lastRx = time.Now()
	t.dpdSent = time.Time{}
}

func (t *SSLPacketTunnel) deadPeer(now time.Time) bool {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	return !t.dpdSent.IsZero() && now.Sub(t.dpdSent) >= t.options.dpdTimeout
}

func (t *SSLPacketTunnel) terminalError() error {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	return t.terminal
}

func (t *SSLPacketTunnel) stoppedError(operationCtx context.Context) error {
	if terminal := t.terminalError(); terminal != nil {
		return terminal
	}
	if err := operationCtx.Err(); err != nil {
		return err
	}
	return t.ctx.Err()
}

func (t *SSLPacketTunnel) stop(terminal error) {
	if terminal != nil {
		t.stateMu.Lock()
		if t.terminal == nil {
			t.terminal = terminal
		}
		t.stateMu.Unlock()
	}
	t.stopOnce.Do(func() {
		t.cancel()
		if err := t.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.closeErr = fmt.Errorf("close ssl packet tunnel: %w", err)
		}
	})
}

func gpstDPDFrame() []byte {
	frame := make([]byte, gpstHeaderLen)
	copy(frame[:4], gpstMagic[:])
	return frame
}
