package tunnel_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

func Test_Dialer_resolvesDomainThroughGatewayDNSOverUDP_andFallsBack(t *testing.T) {
	// Given
	ctx := testContext(t)
	clientPackets, peerPackets := newPacketTunnelPair()
	clientAddr := netip.MustParseAddr("10.0.0.2")
	firstDNS := netip.MustParseAddr("10.0.0.53")
	secondDNS := netip.MustParseAddr("10.0.0.54")
	peer := newPeerStack(t, ctx, peerPackets, firstDNS)
	addPeerAddress(t, peer, secondDNS)
	first := startTestUDPDNSServer(t, listenPeerUDP(t, peer, firstDNS, 53), netip.Addr{}, testDNSRCodeServerFailure, false)
	second := startTestUDPDNSServer(t, listenPeerUDP(t, peer, secondDNS, 53), secondDNS, testDNSRCodeSuccess, false)
	listener := peer.listenTCP(t, secondDNS, 8080)
	defer listener.Close()
	serverDone := serveEchoOnce(listener)
	dialer, err := tunnel.NewDialer(ctx, tunnel.Config{
		Tunnel:           clientPackets,
		LocalAddr:        clientAddr,
		DNSServers:       []netip.Addr{firstDNS, secondDNS},
		DNSSearchDomains: []string{" corp.test. ", "CORP.TEST"},
	})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()

	// When
	conn, err := dialer.DialContext(ctx, "tcp", "service:8080")
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
	if string(response) != "echo:ping" {
		t.Fatalf("response = %q, want echo:ping", response)
	}
	if first.calls.Load() == 0 || second.calls.Load() == 0 {
		t.Fatalf("DNS calls = (%d, %d), want fallback across both servers", first.calls.Load(), second.calls.Load())
	}
	select {
	case query := <-second.queries:
		if query != "service.corp.test." {
			t.Fatalf("DNS query = %q, want service.corp.test.", query)
		}
	case <-ctx.Done():
		t.Fatal("gateway DNS server did not receive query")
	}
	if err := waitServer(ctx, serverDone); err != nil {
		t.Fatalf("echo server error = %v", err)
	}
}

func Test_Dialer_doesNotFallBackToAnotherServer_afterNXDOMAIN(t *testing.T) {
	// Given
	ctx := testContext(t)
	clientPackets, peerPackets := newPacketTunnelPair()
	clientAddr := netip.MustParseAddr("10.0.0.2")
	firstDNS := netip.MustParseAddr("10.0.0.53")
	secondDNS := netip.MustParseAddr("10.0.0.54")
	peer := newPeerStack(t, ctx, peerPackets, firstDNS)
	addPeerAddress(t, peer, secondDNS)
	first := startTestUDPDNSServer(t, listenPeerUDP(t, peer, firstDNS, 53), netip.Addr{}, testDNSRCodeNameError, false)
	second := startTestUDPDNSServer(t, listenPeerUDP(t, peer, secondDNS, 53), secondDNS, testDNSRCodeSuccess, false)
	dialer, err := tunnel.NewDialer(ctx, tunnel.Config{
		Tunnel: clientPackets, LocalAddr: clientAddr, DNSServers: []netip.Addr{firstDNS, secondDNS},
	})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()

	// When
	_, err = dialer.DialContext(ctx, "tcp", "missing.example.test:443")

	// Then
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("DialContext() error = %v, want DNS not found", err)
	}
	if first.calls.Load() == 0 || second.calls.Load() != 0 {
		t.Fatalf("DNS calls = (%d, %d), want NXDOMAIN to be terminal", first.calls.Load(), second.calls.Load())
	}
}

func Test_Dialer_failsClosedForDomain_whenDNSIsNotConfigured(t *testing.T) {
	ctx := testContext(t)
	clientPackets, _ := newPacketTunnelPair()
	dialer, err := tunnel.NewDialer(ctx, tunnel.Config{
		Tunnel: clientPackets, LocalAddr: netip.MustParseAddr("10.0.0.2"),
	})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()

	_, err = dialer.DialContext(ctx, "tcp", "localhost:443")
	if !errors.Is(err, tunnel.ErrDNSUnavailable) {
		t.Fatalf("DialContext() error = %v, want ErrDNSUnavailable", err)
	}
}

func Test_NewDialer_rejectsInvalidDNSServers(t *testing.T) {
	tests := []struct {
		name   string
		server netip.Addr
		want   error
	}{
		{name: "invalid", want: tunnel.ErrInvalidConfig},
		{name: "IPv6", server: netip.MustParseAddr("2001:db8::53"), want: tunnel.ErrIPv6Unsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientPackets, _ := newPacketTunnelPair()
			defer clientPackets.Close()
			_, err := tunnel.NewDialer(context.Background(), tunnel.Config{
				Tunnel: clientPackets, LocalAddr: netip.MustParseAddr("10.0.0.2"), DNSServers: []netip.Addr{test.server},
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("NewDialer() error = %v, want %v", err, test.want)
			}
		})
	}
}
