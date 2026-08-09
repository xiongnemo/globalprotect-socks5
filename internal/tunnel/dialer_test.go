package tunnel_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/netstatus"
	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

func Test_Dialer_DialContext_proxiesTCPOverPacketTunnel_whenTargetIsDomain(t *testing.T) {
	// Given
	ctx := testContext(t)
	clientPackets, peerPackets := newPacketTunnelPair()
	clientAddr := netip.MustParseAddr("10.0.0.2")
	peerAddr := netip.MustParseAddr("10.0.0.1")
	peer := newPeerStack(t, ctx, peerPackets, peerAddr)
	listener := peer.listenTCP(t, peerAddr, 8080)
	defer listener.Close()
	serverDone := serveEchoOnce(listener)
	resolver := tunnel.ResolverFunc(func(_ context.Context, network string, host string) ([]netip.Addr, error) {
		if network != "ip4" {
			return nil, fmt.Errorf("resolver network = %s, want ip4", network)
		}
		if host != "example.test" {
			return nil, fmt.Errorf("resolver host = %s, want example.test", host)
		}
		return []netip.Addr{peerAddr}, nil
	})
	dialer, err := tunnel.NewDialer(ctx, tunnel.Config{
		Tunnel:     clientPackets,
		LocalAddr:  clientAddr,
		Resolver:   resolver,
		DNSServers: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
	})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()

	// When
	conn, err := dialer.DialContext(ctx, "tcp4", "example.test:8080")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	buf := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}

	// Then
	if string(buf) != "echo:ping" {
		t.Fatalf("response = %q, want echo:ping", string(buf))
	}
	if err := waitServer(ctx, serverDone); err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func Test_Dialer_DialContext_rejectsIPv6UntilSupported(t *testing.T) {
	// Given
	ctx := testContext(t)
	clientPackets, _ := newPacketTunnelPair()
	dialer, err := tunnel.NewDialer(ctx, tunnel.Config{
		Tunnel:    clientPackets,
		LocalAddr: netip.MustParseAddr("10.0.0.2"),
	})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()

	// When
	_, err = dialer.DialContext(ctx, "tcp", "[2001:db8::1]:443")

	// Then
	if !errors.Is(err, tunnel.ErrIPv6Unsupported) {
		t.Fatalf("error = %v, want ErrIPv6Unsupported", err)
	}
}

func TestDialerClassifiesRealNetstackConnectionRefusal(t *testing.T) {
	ctx := testContext(t)
	clientPackets, peerPackets := newPacketTunnelPair()
	clientAddr := netip.MustParseAddr("10.0.0.2")
	peerAddr := netip.MustParseAddr("10.0.0.1")
	_ = newPeerStack(t, ctx, peerPackets, peerAddr)
	dialer, err := tunnel.NewDialer(ctx, tunnel.Config{Tunnel: clientPackets, LocalAddr: clientAddr})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()
	_, err = dialer.DialContext(ctx, "tcp4", "10.0.0.1:8080")
	if !errors.Is(err, netstatus.ErrConnectionRefused) {
		t.Fatalf("DialContext() error = %v, want classified connection refusal", err)
	}
}

func Test_Dialer_DialContext_rejectsUnsupportedNetwork(t *testing.T) {
	// Given
	ctx := testContext(t)
	clientPackets, _ := newPacketTunnelPair()
	dialer, err := tunnel.NewDialer(ctx, tunnel.Config{
		Tunnel:    clientPackets,
		LocalAddr: netip.MustParseAddr("10.0.0.2"),
	})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	defer dialer.Close()

	// When
	_, err = dialer.DialContext(ctx, "udp", "10.0.0.1:53")

	// Then
	if !errors.Is(err, tunnel.ErrUnsupportedNetwork) {
		t.Fatalf("error = %v, want ErrUnsupportedNetwork", err)
	}
}

func Test_NewDialer_rejectsIPv6LocalAddress(t *testing.T) {
	// Given
	ctx := testContext(t)
	clientPackets, _ := newPacketTunnelPair()

	// When
	_, err := tunnel.NewDialer(ctx, tunnel.Config{
		Tunnel:    clientPackets,
		LocalAddr: netip.MustParseAddr("2001:db8::2"),
	})

	// Then
	if !errors.Is(err, tunnel.ErrIPv6Unsupported) {
		t.Fatalf("error = %v, want ErrIPv6Unsupported", err)
	}
}
