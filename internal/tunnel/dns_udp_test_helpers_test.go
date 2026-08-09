package tunnel_test

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
)

type testUDPDNSServer struct {
	conn      net.PacketConn
	answer    netip.Addr
	rcode     uint16
	truncated bool
	drop      bool
	queries   chan string
	calls     atomic.Int32
	stop      chan struct{}
	done      chan error
}

func startTestUDPDNSServer(t *testing.T, conn net.PacketConn, answer netip.Addr, rcode uint16, truncated bool) *testUDPDNSServer {
	return startUDPDNSServer(t, conn, answer, rcode, truncated, false)
}

func startBlackholeUDPDNSServer(t *testing.T, conn net.PacketConn) *testUDPDNSServer {
	return startUDPDNSServer(t, conn, netip.Addr{}, testDNSRCodeSuccess, false, true)
}

func startUDPDNSServer(t *testing.T, conn net.PacketConn, answer netip.Addr, rcode uint16, truncated bool, drop bool) *testUDPDNSServer {
	t.Helper()
	server := &testUDPDNSServer{
		conn: conn, answer: answer, rcode: rcode, truncated: truncated, drop: drop,
		queries: make(chan string, 16), stop: make(chan struct{}), done: make(chan error, 1),
	}
	go server.serve()
	t.Cleanup(func() {
		close(server.stop)
		_ = conn.Close()
		select {
		case err := <-server.done:
			if err != nil {
				t.Errorf("UDP DNS server error: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("UDP DNS server did not stop")
		}
	})
	return server
}

func (s *testUDPDNSServer) serve() {
	buf := make([]byte, 4096)
	for {
		n, client, err := s.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.stop:
				s.done <- nil
			default:
				s.done <- fmt.Errorf("read UDP DNS query: %w", err)
			}
			return
		}
		query := append([]byte(nil), buf[:n]...)
		name, _, err := parseDNSQuestion(query)
		if err != nil {
			s.done <- err
			return
		}
		s.calls.Add(1)
		select {
		case s.queries <- name:
		default:
		}
		if s.drop {
			continue
		}
		response, err := buildDNSResponse(query, s.answer, s.rcode, s.truncated)
		if err != nil {
			s.done <- err
			return
		}
		if _, err := s.conn.WriteTo(response, client); err != nil {
			s.done <- fmt.Errorf("write UDP DNS response: %w", err)
			return
		}
	}
}

func listenPeerUDP(t *testing.T, peer *peerStack, addr netip.Addr, port uint16) net.PacketConn {
	t.Helper()
	localAddr := fullAddress(addr, port)
	conn, err := gonet.DialUDP(peer.stack, &localAddr, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP(%s:%d) error = %v", addr, port, err)
	}
	return conn
}
