package app_test

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

type recordingDialer struct {
	mu      sync.Mutex
	network string
	address string
	ready   chan struct{}
	peers   []net.Conn
}

func newRecordingDialer() *recordingDialer {
	return &recordingDialer{ready: make(chan struct{}, 1)}
}

func (d *recordingDialer) DialContext(_ context.Context, network string, address string) (net.Conn, error) {
	client, peer := net.Pipe()
	d.mu.Lock()
	d.network = network
	d.address = address
	d.peers = append(d.peers, peer)
	d.mu.Unlock()
	select {
	case d.ready <- struct{}{}:
	default:
	}
	return client, nil
}

func (d *recordingDialer) wait(t *testing.T) (string, string) {
	t.Helper()
	select {
	case <-d.ready:
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.network, d.address
	case <-time.After(time.Second):
		t.Fatal("serve did not call configured dialer")
		return "", ""
	}
}

func (d *recordingDialer) closePeers() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, peer := range d.peers {
		_ = peer.Close()
	}
}

func connectRequest(host string, port uint16) []byte {
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	request = append(request, []byte(host)...)
	return appendPort(request, port)
}

func connectIPv4Request(addr [4]byte, port uint16) []byte {
	request := []byte{0x05, 0x01, 0x00, 0x01, addr[0], addr[1], addr[2], addr[3]}
	return appendPort(request, port)
}

func appendPort(request []byte, port uint16) []byte {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return append(request, portBytes...)
}

type recordingPacketTunnelConnector struct {
	tunnel *recordingPacketTunnel
	ready  chan app.PacketTunnelRequest
}

func newRecordingPacketTunnelConnector() *recordingPacketTunnelConnector {
	return &recordingPacketTunnelConnector{tunnel: newRecordingPacketTunnel(), ready: make(chan app.PacketTunnelRequest, 1)}
}

func (c *recordingPacketTunnelConnector) ConnectPacketTunnel(_ context.Context, request app.PacketTunnelRequest) (tunnel.PacketTunnel, error) {
	c.ready <- request
	return c.tunnel, nil
}

func (c *recordingPacketTunnelConnector) wait(t *testing.T) app.PacketTunnelRequest {
	t.Helper()
	select {
	case request := <-c.ready:
		return request
	case <-time.After(time.Second):
		t.Fatal("packet tunnel connector was not called")
		return app.PacketTunnelRequest{}
	}
}

type recordingPacketTunnel struct {
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

func newRecordingPacketTunnel() *recordingPacketTunnel {
	return &recordingPacketTunnel{writes: make(chan []byte, 8), closed: make(chan struct{})}
}

func (t *recordingPacketTunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-t.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *recordingPacketTunnel) WritePacket(ctx context.Context, packet []byte) error {
	copyPacket := append([]byte(nil), packet...)
	select {
	case t.writes <- copyPacket:
		return nil
	case <-t.closed:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *recordingPacketTunnel) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

func (t *recordingPacketTunnel) waitWrite(tb testing.TB) []byte {
	tb.Helper()
	select {
	case packet := <-t.writes:
		return packet
	case <-time.After(time.Second):
		tb.Fatal("packet tunnel was not written")
		return nil
	}
}
