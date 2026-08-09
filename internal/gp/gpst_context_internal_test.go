package gp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSSLPacketTunnelConnectContextDoesNotOwnRuntime(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	connectCtx, cancelConnect := context.WithCancel(context.Background())
	lifetimeCtx, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	sendPacket := make(chan struct{})
	serverErr := make(chan error, 1)
	go func() {
		if err := acceptGPSTHandshake(server); err != nil {
			serverErr <- err
			return
		}
		<-sendPacket
		frame, err := EncodeGPSTFrame([]byte{0x45, 0, 0, 20})
		if err == nil {
			_, err = server.Write(frame)
		}
		serverErr <- err
	}()
	tunnel, err := NewSSLPacketTunnelWithLifetime(
		connectCtx, lifetimeCtx, client, testGatewaySession(), testTunnelConfig(),
	)
	if err != nil {
		t.Fatalf("NewSSLPacketTunnelWithLifetime() error = %v", err)
	}
	defer tunnel.Close()

	cancelConnect()
	close(sendPacket)
	readCtx, cancelRead := context.WithTimeout(context.Background(), time.Second)
	defer cancelRead()
	packet, err := tunnel.ReadPacket(readCtx)
	if err != nil {
		t.Fatalf("ReadPacket() after connect cancellation error = %v", err)
	}
	if !bytes.Equal(packet, []byte{0x45, 0, 0, 20}) {
		t.Fatalf("packet = %x", packet)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestSSLPacketTunnelLifetimeCancellationUnblocksBackgroundRead(t *testing.T) {
	tunnel, probe, cancelLifetime := newLifetimeTestTunnel(t, defaultGPSTRuntimeOptions())
	errCh := make(chan error, 1)
	go func() {
		_, err := tunnel.ReadPacket(context.Background())
		errCh <- err
	}()
	waitSignal(t, probe.packetRead, "background packet read")

	cancelLifetime()
	waitSignal(t, probe.closed, "underlying connection close")
	if err := waitError(t, errCh); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadPacket() error = %v, want context canceled", err)
	}
	if terminal := tunnel.terminalError(); terminal != nil {
		t.Fatalf("terminal error = %v after normal lifetime cancellation", terminal)
	}
}

func TestSSLPacketTunnelLifetimeCancellationUnblocksBackgroundWrite(t *testing.T) {
	tunnel, probe, cancelLifetime := newLifetimeTestTunnel(t, defaultGPSTRuntimeOptions())
	errCh := make(chan error, 1)
	go func() {
		errCh <- tunnel.WritePacket(context.Background(), []byte{0x45, 0, 0, 20})
	}()
	waitSignal(t, probe.packetWrite, "background packet write")

	cancelLifetime()
	waitSignal(t, probe.closed, "underlying connection close")
	if err := waitError(t, errCh); !errors.Is(err, context.Canceled) {
		t.Fatalf("WritePacket() error = %v, want context canceled", err)
	}
	if terminal := tunnel.terminalError(); terminal != nil {
		t.Fatalf("terminal error = %v after normal lifetime cancellation", terminal)
	}
}

func TestSSLPacketTunnelLifetimeCancellationDuringDPDIsNotTerminal(t *testing.T) {
	options := gpstRuntimeOptions{
		handshakeTimeout: time.Second, dpdInterval: 5 * time.Millisecond,
		dpdTimeout: 50 * time.Millisecond, writeTimeout: time.Second,
	}
	tunnel, probe, cancelLifetime := newLifetimeTestTunnel(t, options)
	waitSignal(t, probe.packetWrite, "DPD write")

	cancelLifetime()
	waitSignal(t, probe.closed, "underlying connection close")
	if err := tunnel.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if terminal := tunnel.terminalError(); terminal != nil {
		t.Fatalf("terminal error = %v after normal lifetime cancellation", terminal)
	}
}

type gpstProbeConn struct {
	net.Conn
	packetRead  chan struct{}
	packetWrite chan struct{}
	closed      chan struct{}
	readOnce    sync.Once
	writeOnce   sync.Once
	closeOnce   sync.Once
}

func newGPSTProbeConn(conn net.Conn) *gpstProbeConn {
	return &gpstProbeConn{
		Conn: conn, packetRead: make(chan struct{}), packetWrite: make(chan struct{}),
		closed: make(chan struct{}),
	}
}

func (c *gpstProbeConn) Read(buf []byte) (int, error) {
	if len(buf) == gpstHeaderLen {
		c.readOnce.Do(func() { close(c.packetRead) })
	}
	return c.Conn.Read(buf)
}

func (c *gpstProbeConn) Write(buf []byte) (int, error) {
	if len(buf) >= len(gpstMagic) && bytes.Equal(buf[:len(gpstMagic)], gpstMagic[:]) {
		c.writeOnce.Do(func() { close(c.packetWrite) })
	}
	return c.Conn.Write(buf)
}

func (c *gpstProbeConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func newLifetimeTestTunnel(t *testing.T, options gpstRuntimeOptions) (*SSLPacketTunnel, *gpstProbeConn, context.CancelFunc) {
	t.Helper()
	client, server := net.Pipe()
	probe := newGPSTProbeConn(client)
	lifetimeCtx, cancelLifetime := context.WithCancel(context.Background())
	serverErr := make(chan error, 1)
	go func() { serverErr <- acceptGPSTHandshake(server) }()
	tunnel, err := newSSLPacketTunnelWithLifetime(
		context.Background(), lifetimeCtx, probe, testGatewaySession(), testTunnelConfig(), options,
	)
	if err != nil {
		cancelLifetime()
		server.Close()
		t.Fatalf("newSSLPacketTunnelWithLifetime() error = %v", err)
	}
	if err := <-serverErr; err != nil {
		cancelLifetime()
		server.Close()
		t.Fatalf("server handshake error = %v", err)
	}
	t.Cleanup(func() {
		cancelLifetime()
		_ = tunnel.Close()
		_ = server.Close()
	})
	return tunnel, probe, cancelLifetime
}

func waitSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitError(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for I/O error")
		return nil
	}
}
