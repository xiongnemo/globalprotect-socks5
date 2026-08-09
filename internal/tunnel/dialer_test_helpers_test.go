package tunnel_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/noisysockets/netstack/pkg/buffer"
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/link/channel"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/udp"
	"github.com/xiongnemo/globalprotect-socks5/internal/tunnel"
)

const testNICID = tcpip.NICID(1)

type memoryPacketTunnel struct {
	incoming <-chan []byte
	outgoing chan<- []byte
	closed   chan struct{}
	once     sync.Once
}

func newPacketTunnelPair() (*memoryPacketTunnel, *memoryPacketTunnel) {
	leftToRight := make(chan []byte, 64)
	rightToLeft := make(chan []byte, 64)
	left := &memoryPacketTunnel{incoming: rightToLeft, outgoing: leftToRight, closed: make(chan struct{})}
	right := &memoryPacketTunnel{incoming: leftToRight, outgoing: rightToLeft, closed: make(chan struct{})}
	return left, right
}

func (t *memoryPacketTunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-t.incoming:
		return append([]byte(nil), packet...), nil
	case <-t.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *memoryPacketTunnel) WritePacket(ctx context.Context, packet []byte) error {
	copyPacket := append([]byte(nil), packet...)
	select {
	case t.outgoing <- copyPacket:
		return nil
	case <-t.closed:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *memoryPacketTunnel) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

type peerStack struct {
	stack  *stack.Stack
	linkEP *channel.Endpoint
	tunnel tunnel.PacketTunnel
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newPeerStack(t *testing.T, parent context.Context, packetTunnel tunnel.PacketTunnel, addr netip.Addr) *peerStack {
	t.Helper()
	s, linkEP := newTestStack(t, addr)
	ctx, cancel := context.WithCancel(parent)
	peer := &peerStack{stack: s, linkEP: linkEP, tunnel: packetTunnel, cancel: cancel}
	peer.wg.Add(2)
	go peer.readPackets(ctx)
	go peer.writePackets(ctx)
	t.Cleanup(func() { peer.close() })
	return peer
}

func (p *peerStack) listenTCP(t *testing.T, addr netip.Addr, port uint16) net.Listener {
	t.Helper()
	listener, err := gonet.ListenTCP(p.stack, fullAddress(addr, port), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	return listener
}

func (p *peerStack) close() {
	p.cancel()
	p.linkEP.Close()
	_ = p.tunnel.Close()
	p.stack.Close()
	p.wg.Wait()
	p.stack.Wait()
}

func (p *peerStack) readPackets(ctx context.Context) {
	defer p.wg.Done()
	for {
		packet, err := p.tunnel.ReadPacket(ctx)
		if err != nil {
			return
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		p.linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()
	}
}

func (p *peerStack) writePackets(ctx context.Context) {
	defer p.wg.Done()
	for {
		pkt := p.linkEP.ReadContext(ctx)
		if pkt == nil {
			return
		}
		buf := pkt.ToBuffer()
		packet := append([]byte(nil), buf.Flatten()...)
		buf.Release()
		pkt.DecRef()
		if err := p.tunnel.WritePacket(ctx, packet); err != nil {
			return
		}
	}
}

func newTestStack(t *testing.T, addr netip.Addr) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	linkEP := channel.New(64, 1500, "")
	if err := s.CreateNIC(testNICID, linkEP); err != nil {
		t.Fatalf("CreateNIC() error = %s", err)
	}
	protocolAddr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpipAddr(addr).WithPrefix()}
	if err := s.AddProtocolAddress(testNICID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress() error = %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: testNICID}})
	return s, linkEP
}

func serveEchoOnce(listener net.Listener) <-chan error {
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			done <- fmt.Errorf("read request: %w", err)
			return
		}
		_, err = conn.Write([]byte("echo:" + string(buf)))
		done <- err
	}()
	return done
}

func waitServer(ctx context.Context, done <-chan error) error {
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func fullAddress(addr netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: testNICID, Addr: tcpipAddr(addr), Port: port}
}

func tcpipAddr(addr netip.Addr) tcpip.Address {
	return tcpip.AddrFrom4(addr.As4())
}
