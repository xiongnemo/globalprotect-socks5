package gp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestSSLPacketTunnelSendsDPDAndContinuesAfterResponse(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() {
		if err := acceptGPSTHandshake(server); err != nil {
			serverErr <- err
			return
		}
		frame := make([]byte, gpstHeaderLen)
		if _, err := io.ReadFull(server, frame); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(frame, gpstDPDFrame()) {
			serverErr <- errors.New("unexpected DPD frame")
			return
		}
		if _, err := server.Write(gpstDPDFrame()); err != nil {
			serverErr <- err
			return
		}
		data, err := EncodeGPSTFrame([]byte{0x45, 0, 0, 20})
		if err == nil {
			_, err = server.Write(data)
		}
		serverErr <- err
	}()
	tunnel, err := newSSLPacketTunnel(context.Background(), client, testGatewaySession(), testTunnelConfig(), gpstRuntimeOptions{
		handshakeTimeout: time.Second, dpdInterval: 10 * time.Millisecond, dpdTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("newSSLPacketTunnel() error = %v", err)
	}
	defer tunnel.Close()
	packet, err := tunnel.ReadPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if !bytes.Equal(packet, []byte{0x45, 0, 0, 20}) {
		t.Fatalf("packet = %#v", packet)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestSSLPacketTunnelDetectsDeadPeer(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		if acceptGPSTHandshake(server) != nil {
			return
		}
		frame := make([]byte, gpstHeaderLen)
		_, _ = io.ReadFull(server, frame)
	}()
	tunnel, err := newSSLPacketTunnel(context.Background(), client, testGatewaySession(), testTunnelConfig(), gpstRuntimeOptions{
		handshakeTimeout: time.Second, dpdInterval: 10 * time.Millisecond, dpdTimeout: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("newSSLPacketTunnel() error = %v", err)
	}
	defer tunnel.Close()
	_, err = tunnel.ReadPacket(context.Background())
	if !errors.Is(err, ErrGPSTDeadPeer) {
		t.Fatalf("ReadPacket() error = %v, want ErrGPSTDeadPeer", err)
	}
}

func TestSSLPacketTunnelSignalsRekeyDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() { _ = acceptGPSTHandshake(server) }()
	tunnel, err := newSSLPacketTunnel(context.Background(), client, testGatewaySession(), testTunnelConfig(), gpstRuntimeOptions{
		handshakeTimeout: time.Second, dpdInterval: time.Second, dpdTimeout: 2 * time.Second,
		rekeyAfter: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("newSSLPacketTunnel() error = %v", err)
	}
	defer tunnel.Close()
	_, err = tunnel.ReadPacket(context.Background())
	if !errors.Is(err, ErrGPSTRekeyDue) {
		t.Fatalf("ReadPacket() error = %v, want ErrGPSTRekeyDue", err)
	}
}

func TestSSLPacketTunnelHandshakeTimesOut(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		reader := bufio.NewReader(server)
		_, _ = reader.ReadString('\n')
		_, _ = reader.ReadString('\n')
	}()
	_, err := newSSLPacketTunnel(context.Background(), client, testGatewaySession(), testTunnelConfig(), gpstRuntimeOptions{
		handshakeTimeout: 20 * time.Millisecond, dpdInterval: time.Second, dpdTimeout: 2 * time.Second,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("newSSLPacketTunnel() error = %v, want deadline exceeded", err)
	}
}

func TestSSLPacketTunnelDPDUsesReceiveSilenceDespiteRecentTransmit(t *testing.T) {
	now := time.Now()
	tunnel := &SSLPacketTunnel{
		lastRx: now.Add(-time.Minute), lastTx: now,
		options: gpstRuntimeOptions{dpdInterval: 10 * time.Second},
	}
	if !tunnel.shouldSendDPD(now) {
		t.Fatal("shouldSendDPD() = false after receive silence and recent transmit")
	}
}

func TestSSLPacketTunnelDPDMarksSentOnlyAfterWriteLock(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tunnel := &SSLPacketTunnel{
		conn: client, ctx: context.Background(), writeLock: make(chan struct{}, 1),
		options: gpstRuntimeOptions{writeTimeout: time.Second},
	}

	blockedCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := tunnel.writeDPD(blockedCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("writeDPD() error = %v, want deadline exceeded", err)
	}
	if sent := tunnel.dpdSentTime(); !sent.IsZero() {
		t.Fatalf("dpdSent = %v before write lock was acquired", sent)
	}

	releasedAt := time.Now()
	tunnel.writeLock <- struct{}{}
	errCh := make(chan error, 1)
	go func() { errCh <- tunnel.writeDPD(context.Background()) }()
	sent := waitForDPDSent(t, tunnel)
	if sent.Before(releasedAt) {
		t.Fatalf("dpdSent = %v, before lock release at %v", sent, releasedAt)
	}
	frame := make([]byte, gpstHeaderLen)
	if _, err := io.ReadFull(server, frame); err != nil {
		t.Fatalf("read DPD frame: %v", err)
	}
	if !bytes.Equal(frame, gpstDPDFrame()) {
		t.Fatalf("frame = %x, want DPD frame", frame)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("writeDPD() error = %v", err)
	}
}

func (t *SSLPacketTunnel) dpdSentTime() time.Time {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	return t.dpdSent
}

func waitForDPDSent(t *testing.T, tunnel *SSLPacketTunnel) time.Time {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("timed out waiting for DPD sent timestamp")
		case <-ticker.C:
			if sent := tunnel.dpdSentTime(); !sent.IsZero() {
				return sent
			}
		}
	}
}

func acceptGPSTHandshake(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}
	_, err := conn.Write([]byte(gpstStartTunnel))
	return err
}

func testGatewaySession() GatewaySession {
	return GatewaySession{User: "alice", AuthCookie: Secret{raw: "cookie"}}
}

func testTunnelConfig() TunnelConfig {
	return TunnelConfig{SSLTunnelURL: "/ssl-tunnel-connect.sslvpn"}
}
