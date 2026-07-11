package tunnel

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/noisysockets/netstack/pkg/buffer"
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
)

func (d *Dialer) readPackets(ctx context.Context) {
	defer d.wg.Done()
	for {
		packet, err := d.tunnel.ReadPacket(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.fail(fmt.Errorf("read packet tunnel: %w", err))
			return
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		d.linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()
	}
}

func (d *Dialer) writePackets(ctx context.Context) {
	defer d.wg.Done()
	for {
		pkt := d.linkEP.ReadContext(ctx)
		if pkt == nil {
			return
		}
		packet := flattenPacket(pkt)
		pkt.DecRef()
		if err := d.tunnel.WritePacket(ctx, packet); err != nil {
			if ctx.Err() != nil {
				return
			}
			d.fail(fmt.Errorf("write packet tunnel: %w", err))
			return
		}
	}
}

func flattenPacket(pkt *stack.PacketBuffer) []byte {
	buf := pkt.ToBuffer()
	defer buf.Release()
	return append([]byte(nil), buf.Flatten()...)
}

func tcpipAddr(addr netip.Addr) tcpip.Address {
	return tcpip.AddrFrom4(addr.As4())
}
