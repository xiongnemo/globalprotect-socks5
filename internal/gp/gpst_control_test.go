package gp_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_SSLPacketTunnel_ReadPacket_ignoresControlFrameBeforeIPv4Packet(t *testing.T) {
	// Given
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	session := gp.GatewaySession{User: "alice@example.test", AuthCookie: mustSecret(t, "auth-cookie")}
	config := gp.TunnelConfig{SSLTunnelURL: "/ssl-tunnel-connect.sslvpn"}
	go func() {
		request := make([]byte, 512)
		_, _ = serverConn.Read(request)
		_, _ = serverConn.Write([]byte("START_TUNNEL"))
		_, _ = serverConn.Write(gpstControlFrame())
		frame, err := gp.EncodeGPSTFrame([]byte{0x45, 0x00, 0x00, 0x14})
		if err != nil {
			return
		}
		_, _ = serverConn.Write(frame)
	}()
	tunnel, err := gp.NewSSLPacketTunnel(context.Background(), clientConn, session, config)
	if err != nil {
		t.Fatalf("NewSSLPacketTunnel() error = %v", err)
	}
	defer tunnel.Close()

	// When
	packet, err := tunnel.ReadPacket(context.Background())

	// Then
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if !bytes.Equal(packet, []byte{0x45, 0x00, 0x00, 0x14}) {
		t.Fatalf("packet = %#v", packet)
	}
}

func gpstControlFrame() []byte {
	frame := make([]byte, 16)
	copy(frame[:4], []byte{0x1a, 0x2b, 0x3c, 0x4d})
	binary.BigEndian.PutUint16(frame[4:6], 0)
	binary.BigEndian.PutUint16(frame[6:8], 0)
	return frame
}
