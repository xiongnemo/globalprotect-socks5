package gp

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

type contextReader struct {
	ctx  context.Context
	conn net.Conn
}

func (r contextReader) Read(buf []byte) (int, error) {
	if err := readFullContext(r.ctx, r.conn, buf); err != nil {
		return 0, err
	}
	return len(buf), nil
}

func readFullContext(ctx context.Context, conn net.Conn, buf []byte) error {
	stop := deadlineOnCancel(ctx, conn.SetReadDeadline)
	_, err := io.ReadFull(conn, buf)
	stop()
	if resetErr := conn.SetReadDeadline(time.Time{}); resetErr != nil && err == nil {
		return fmt.Errorf("reset read deadline: %w", resetErr)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("read from tunnel: %w", err)
	}
	return nil
}

func writeAllContext(ctx context.Context, conn net.Conn, data []byte) error {
	for len(data) > 0 {
		stop := deadlineOnCancel(ctx, conn.SetWriteDeadline)
		n, err := conn.Write(data)
		stop()
		if resetErr := conn.SetWriteDeadline(time.Time{}); resetErr != nil && err == nil {
			return fmt.Errorf("reset write deadline: %w", resetErr)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			return fmt.Errorf("write to tunnel: %w", err)
		}
		data = data[n:]
	}
	return nil
}

func deadlineOnCancel(ctx context.Context, setDeadline func(time.Time) error) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = setDeadline(time.Now())
		close(done)
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}
