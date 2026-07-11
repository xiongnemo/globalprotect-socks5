package app_test

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
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

func appendPort(request []byte, port uint16) []byte {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return append(request, portBytes...)
}
