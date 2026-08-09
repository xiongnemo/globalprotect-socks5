package tunnel_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
)

const (
	testDNSRCodeSuccess       = uint16(0)
	testDNSRCodeServerFailure = uint16(2)
	testDNSRCodeNameError     = uint16(3)
)

type testDNSServer struct {
	listener net.Listener
	answer   netip.Addr
	rcode    uint16
	queries  chan string
	calls    atomic.Int32
	stop     chan struct{}
	done     chan error
}

func startTestTCPDNSServer(t *testing.T, listener net.Listener, answer netip.Addr, rcode uint16) *testDNSServer {
	t.Helper()
	server := &testDNSServer{
		listener: listener,
		answer:   answer,
		rcode:    rcode,
		queries:  make(chan string, 16),
		stop:     make(chan struct{}),
		done:     make(chan error, 1),
	}
	go server.serve()
	t.Cleanup(func() {
		close(server.stop)
		_ = listener.Close()
		select {
		case err := <-server.done:
			if err != nil {
				t.Errorf("DNS server error: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("DNS server did not stop")
		}
	})
	return server
}

func (s *testDNSServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				s.done <- nil
			default:
				s.done <- fmt.Errorf("accept DNS connection: %w", err)
			}
			return
		}
		s.calls.Add(1)
		if err := s.answerQuery(conn); err != nil {
			_ = conn.Close()
			s.done <- err
			return
		}
		_ = conn.Close()
	}
}

func (s *testDNSServer) answerQuery(conn net.Conn) error {
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return fmt.Errorf("read DNS query length: %w", err)
	}
	query := make([]byte, int(binary.BigEndian.Uint16(length[:])))
	if _, err := io.ReadFull(conn, query); err != nil {
		return fmt.Errorf("read DNS query: %w", err)
	}
	name, _, err := parseDNSQuestion(query)
	if err != nil {
		return err
	}
	select {
	case s.queries <- name:
	default:
	}
	response, err := buildDNSResponse(query, s.answer, s.rcode, false)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(length[:], uint16(len(response)))
	if _, err := conn.Write(append(length[:], response...)); err != nil {
		return fmt.Errorf("write DNS response: %w", err)
	}
	return nil
}

func buildDNSResponse(query []byte, answer netip.Addr, rcode uint16, truncated bool) ([]byte, error) {
	_, questionEnd, err := parseDNSQuestion(query)
	if err != nil {
		return nil, err
	}
	response := make([]byte, 12, 12+questionEnd-12+16)
	copy(response[:2], query[:2])
	flags := uint16(0x8180) | rcode
	if truncated {
		flags |= 0x0200
	}
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	if !truncated && rcode == testDNSRCodeSuccess && answer.Is4() {
		binary.BigEndian.PutUint16(response[6:8], 1)
	}
	response = append(response, query[12:questionEnd]...)
	if truncated || rcode != testDNSRCodeSuccess || !answer.Is4() {
		return response, nil
	}
	response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	ip := answer.As4()
	return append(response, ip[:]...), nil
}

func parseDNSQuestion(query []byte) (string, int, error) {
	if len(query) < 17 {
		return "", 0, errors.New("short DNS query")
	}
	labels := make([]string, 0, 4)
	offset := 12
	for {
		if offset >= len(query) {
			return "", 0, errors.New("truncated DNS question")
		}
		length := int(query[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xc0 != 0 || offset+length > len(query) {
			return "", 0, errors.New("invalid DNS question name")
		}
		labels = append(labels, string(query[offset:offset+length]))
		offset += length
	}
	if offset+4 > len(query) {
		return "", 0, errors.New("truncated DNS question type")
	}
	return strings.Join(labels, ".") + ".", offset + 4, nil
}

func addPeerAddress(t *testing.T, peer *peerStack, addr netip.Addr) {
	t.Helper()
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpipAddr(addr).WithPrefix(),
	}
	if err := peer.stack.AddProtocolAddress(testNICID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%s) error = %s", addr, err)
	}
}
