package gp_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_GPSTFrame_roundTripsIPv4Packet(t *testing.T) {
	// Given
	packet := []byte{0x45, 0x00, 0x00, 0x14}

	// When
	frame, err := gp.EncodeGPSTFrame(packet)
	if err != nil {
		t.Fatalf("EncodeGPSTFrame() error = %v", err)
	}
	got, err := gp.DecodeGPSTFrame(bytes.NewReader(frame))

	// Then
	if err != nil {
		t.Fatalf("DecodeGPSTFrame() error = %v", err)
	}
	if !bytes.Equal(got, packet) {
		t.Fatalf("packet = %#v, want %#v", got, packet)
	}
}

func Test_DecodeGPSTFrame_rejectsInvalidMagic(t *testing.T) {
	// Given
	frame, err := gp.EncodeGPSTFrame([]byte{0x45, 0x00})
	if err != nil {
		t.Fatalf("EncodeGPSTFrame() error = %v", err)
	}
	binary.BigEndian.PutUint32(frame[:4], 0x11223344)

	// When
	_, err = gp.DecodeGPSTFrame(bytes.NewReader(frame))

	// Then
	if !errors.Is(err, gp.ErrInvalidGPSTFrame) {
		t.Fatalf("error = %v, want ErrInvalidGPSTFrame", err)
	}
}

func Test_DecodeGPSTFrame_rejectsUnsupportedEtherType(t *testing.T) {
	// Given
	frame, err := gp.EncodeGPSTFrame([]byte{0x45, 0x00})
	if err != nil {
		t.Fatalf("EncodeGPSTFrame() error = %v", err)
	}
	binary.BigEndian.PutUint16(frame[4:6], 0x86dd)

	// When
	_, err = gp.DecodeGPSTFrame(bytes.NewReader(frame))

	// Then
	if !errors.Is(err, gp.ErrInvalidGPSTFrame) {
		t.Fatalf("error = %v, want ErrInvalidGPSTFrame", err)
	}
}

func Test_DecodeGPSTFrame_rejectsInvalidFixedHeaderBytes(t *testing.T) {
	// Given
	frame, err := gp.EncodeGPSTFrame([]byte{0x45, 0x00})
	if err != nil {
		t.Fatalf("EncodeGPSTFrame() error = %v", err)
	}
	frame[8] = 0x02

	// When
	_, err = gp.DecodeGPSTFrame(bytes.NewReader(frame))

	// Then
	if !errors.Is(err, gp.ErrInvalidGPSTFrame) {
		t.Fatalf("error = %v, want ErrInvalidGPSTFrame", err)
	}
}

func Test_EncodeGPSTFrame_rejectsPacket_whenLengthExceedsUint16(t *testing.T) {
	// Given
	packet := []byte(strings.Repeat("x", 1<<16))

	// When
	_, err := gp.EncodeGPSTFrame(packet)

	// Then
	if !errors.Is(err, gp.ErrInvalidGPSTFrame) {
		t.Fatalf("error = %v, want ErrInvalidGPSTFrame", err)
	}
}

func Test_SSLPacketTunnel_connectsAfterStartTunnelMarker(t *testing.T) {
	// Given
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	session := gp.GatewaySession{User: "alice@example.test", AuthCookie: mustSecret(t, "auth-cookie")}
	config := gp.TunnelConfig{SSLTunnelURL: "/ssl-tunnel-connect.sslvpn"}
	errCh := make(chan error, 1)
	go func() {
		request := make([]byte, 512)
		n, err := serverConn.Read(request)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Contains(request[:n], []byte("GET /ssl-tunnel-connect.sslvpn?")) {
			errCh <- errors.New("missing ssl tunnel request")
			return
		}
		if bytes.Contains(request[:n], []byte("pre-cookie")) {
			errCh <- errors.New("request leaked prelogin cookie")
			return
		}
		_, err = serverConn.Write([]byte("START_TUNNEL"))
		errCh <- err
	}()

	// When
	tunnel, err := gp.NewSSLPacketTunnel(context.Background(), clientConn, session, config)

	// Then
	if err != nil {
		t.Fatalf("NewSSLPacketTunnel() error = %v", err)
	}
	defer tunnel.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func Test_SSLPacketTunnel_roundTripsPacket(t *testing.T) {
	// Given
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	session := gp.GatewaySession{User: "alice@example.test", AuthCookie: mustSecret(t, "auth-cookie")}
	config := gp.TunnelConfig{SSLTunnelURL: "/ssl-tunnel-connect.sslvpn"}
	go func() {
		request := make([]byte, 512)
		_, _ = serverConn.Read(request)
		_, _ = serverConn.Write([]byte("START_TUNNEL"))
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

func Test_SSLPacketTunnel_writesPacketFrame(t *testing.T) {
	// Given
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	session := gp.GatewaySession{User: "alice@example.test", AuthCookie: mustSecret(t, "auth-cookie")}
	config := gp.TunnelConfig{SSLTunnelURL: "/ssl-tunnel-connect.sslvpn"}
	readCh := make(chan []byte, 1)
	go func() {
		request := make([]byte, 512)
		_, _ = serverConn.Read(request)
		_, _ = serverConn.Write([]byte("START_TUNNEL"))
		frame := make([]byte, 20)
		_, _ = serverConn.Read(frame)
		readCh <- frame
	}()
	tunnel, err := gp.NewSSLPacketTunnel(context.Background(), clientConn, session, config)
	if err != nil {
		t.Fatalf("NewSSLPacketTunnel() error = %v", err)
	}
	defer tunnel.Close()

	// When
	err = tunnel.WritePacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14})

	// Then
	if err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	got, err := gp.DecodeGPSTFrame(bytes.NewReader(<-readCh))
	if err != nil {
		t.Fatalf("DecodeGPSTFrame() error = %v", err)
	}
	if !bytes.Equal(got, []byte{0x45, 0x00, 0x00, 0x14}) {
		t.Fatalf("packet = %#v", got)
	}
}

func mustSecret(t *testing.T, raw string) gp.Secret {
	t.Helper()
	secret, err := gp.NewSecret(raw)
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	return secret
}
