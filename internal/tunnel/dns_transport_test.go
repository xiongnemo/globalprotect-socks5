package tunnel_test

import (
	"io"
	"net/netip"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

func Test_Dialer_retriesTruncatedUDPResponseOverTCP(t *testing.T) {
	// Given
	ctx := testContext(t)
	clientPackets, peerPackets := newPacketTunnelPair()
	clientAddr := netip.MustParseAddr("10.0.0.2")
	dnsAddr := netip.MustParseAddr("10.0.0.53")
	peer := newPeerStack(t, ctx, peerPackets, dnsAddr)
	udpServer := startTestUDPDNSServer(t, listenPeerUDP(t, peer, dnsAddr, 53), netip.Addr{}, testDNSRCodeSuccess, true)
	tcpServer := startTestTCPDNSServer(t, peer.listenTCP(t, dnsAddr, 53), dnsAddr, testDNSRCodeSuccess)
	listener := peer.listenTCP(t, dnsAddr, 8080)
	defer listener.Close()
	serverDone := serveEchoOnce(listener)
	dialer, err := tunnel.NewDialer(ctx, tunnel.Config{
		Tunnel: clientPackets, LocalAddr: clientAddr, DNSServers: []netip.Addr{dnsAddr},
	})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()

	// When
	conn, err := dialer.DialContext(ctx, "tcp", "truncated.example.test:8080")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	response := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}

	// Then
	if udpServer.calls.Load() == 0 || tcpServer.calls.Load() == 0 {
		t.Fatalf("DNS calls UDP=%d TCP=%d, want UDP then TCP", udpServer.calls.Load(), tcpServer.calls.Load())
	}
	if err := waitServer(ctx, serverDone); err != nil {
		t.Fatalf("echo server error = %v", err)
	}
}

func Test_Dialer_fallsBackToNextGatewayDNS_afterUDPTimeout(t *testing.T) {
	// Given
	ctx := testContext(t)
	clientPackets, peerPackets := newPacketTunnelPair()
	clientAddr := netip.MustParseAddr("10.0.0.2")
	firstDNS := netip.MustParseAddr("10.0.0.53")
	secondDNS := netip.MustParseAddr("10.0.0.54")
	peer := newPeerStack(t, ctx, peerPackets, firstDNS)
	addPeerAddress(t, peer, secondDNS)
	first := startBlackholeUDPDNSServer(t, listenPeerUDP(t, peer, firstDNS, 53))
	second := startTestUDPDNSServer(t, listenPeerUDP(t, peer, secondDNS, 53), secondDNS, testDNSRCodeSuccess, false)
	listener := peer.listenTCP(t, secondDNS, 8080)
	defer listener.Close()
	serverDone := serveEchoOnce(listener)
	dialer, err := tunnel.NewDialer(ctx, tunnel.Config{
		Tunnel: clientPackets, LocalAddr: clientAddr, DNSServers: []netip.Addr{firstDNS, secondDNS},
	})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()

	// When
	conn, err := dialer.DialContext(ctx, "tcp", "timeout.example.test:8080")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	response := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}

	// Then
	if first.calls.Load() == 0 || second.calls.Load() == 0 {
		t.Fatalf("DNS calls = (%d, %d), want timeout fallback", first.calls.Load(), second.calls.Load())
	}
	if err := waitServer(ctx, serverDone); err != nil {
		t.Fatalf("echo server error = %v", err)
	}
}
