package gp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

var (
	ErrInvalidGPSTFrame     = errors.New("gp: invalid gpst frame")
	ErrInvalidGPSTHandshake = errors.New("gp: invalid gpst handshake")
)

const (
	gpstHeaderLen     = 16
	gpstEtherControl  = 0x0000
	gpstEtherIPv4     = 0x0800
	gpstStartTunnel   = "START_TUNNEL"
	maxGPSTPayloadLen = 1<<16 - 1
)

var gpstMagic = [4]byte{0x1a, 0x2b, 0x3c, 0x4d}
var gpstControlHeader = [8]byte{}
var gpstFixedHeader = [8]byte{0x01, 0, 0, 0, 0, 0, 0, 0}

type SSLPacketTunnel struct {
	conn net.Conn
}

func EncodeGPSTFrame(packet []byte) ([]byte, error) {
	if len(packet) > maxGPSTPayloadLen {
		return nil, fmt.Errorf("gpst payload length %d: %w", len(packet), ErrInvalidGPSTFrame)
	}
	frame := make([]byte, gpstHeaderLen+len(packet))
	copy(frame[:4], gpstMagic[:])
	binary.BigEndian.PutUint16(frame[4:6], gpstEtherIPv4)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(packet)))
	copy(frame[8:gpstHeaderLen], gpstFixedHeader[:])
	copy(frame[gpstHeaderLen:], packet)
	return frame, nil
}

func DecodeGPSTFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, gpstHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read gpst header: %w", err)
	}
	return decodeGPSTPayload(r, header)
}

func NewSSLPacketTunnel(ctx context.Context, conn net.Conn, session GatewaySession, config TunnelConfig) (*SSLPacketTunnel, error) {
	request, err := sslTunnelRequest(session, config)
	if err != nil {
		return nil, err
	}
	if err := writeAllContext(ctx, conn, []byte(request)); err != nil {
		return nil, fmt.Errorf("write tunnel request: %w", err)
	}
	marker := make([]byte, len(gpstStartTunnel))
	if err := readFullContext(ctx, conn, marker); err != nil {
		return nil, fmt.Errorf("read tunnel marker: %w", err)
	}
	if string(marker) != gpstStartTunnel {
		return nil, fmt.Errorf("tunnel marker %q: %w", string(marker), ErrInvalidGPSTHandshake)
	}
	return &SSLPacketTunnel{conn: conn}, nil
}

func (t *SSLPacketTunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	reader := contextReader{ctx: ctx, conn: t.conn}
	for {
		header := make([]byte, gpstHeaderLen)
		if err := readFullContext(ctx, t.conn, header); err != nil {
			return nil, fmt.Errorf("read gpst header: %w", err)
		}
		packet, data, err := readGPSTPacket(reader, header)
		if err != nil {
			return nil, err
		}
		if data {
			return packet, nil
		}
	}
}

func (t *SSLPacketTunnel) WritePacket(ctx context.Context, packet []byte) error {
	frame, err := EncodeGPSTFrame(packet)
	if err != nil {
		return err
	}
	if err := writeAllContext(ctx, t.conn, frame); err != nil {
		return fmt.Errorf("write gpst packet: %w", err)
	}
	return nil
}

func (t *SSLPacketTunnel) Close() error {
	if err := t.conn.Close(); err != nil {
		return fmt.Errorf("close ssl packet tunnel: %w", err)
	}
	return nil
}

func decodeGPSTPayload(r io.Reader, header []byte) ([]byte, error) {
	payload, data, err := readGPSTPacket(r, header)
	if err != nil {
		return nil, err
	}
	if !data {
		return nil, fmt.Errorf("gpst control frame: %w", ErrInvalidGPSTFrame)
	}
	return payload, nil
}

func readGPSTPacket(r io.Reader, header []byte) ([]byte, bool, error) {
	if len(header) != gpstHeaderLen || !bytes.Equal(header[:4], gpstMagic[:]) {
		return nil, false, fmt.Errorf("gpst header: %w", ErrInvalidGPSTFrame)
	}
	etherType := binary.BigEndian.Uint16(header[4:6])
	if etherType == gpstEtherControl && bytes.Equal(header[8:gpstHeaderLen], gpstControlHeader[:]) {
		if err := discardGPSTPayload(r, header); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	if etherType != gpstEtherIPv4 {
		return nil, false, fmt.Errorf("gpst ethertype: %w", ErrInvalidGPSTFrame)
	}
	if !bytes.Equal(header[8:gpstHeaderLen], gpstFixedHeader[:]) {
		return nil, false, fmt.Errorf("gpst fixed header: %w", ErrInvalidGPSTFrame)
	}
	length := int(binary.BigEndian.Uint16(header[6:8]))
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, false, fmt.Errorf("read gpst payload: %w", err)
	}
	return payload, true, nil
}

func discardGPSTPayload(r io.Reader, header []byte) error {
	length := int(binary.BigEndian.Uint16(header[6:8]))
	if length == 0 {
		return nil
	}
	if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
		return fmt.Errorf("read gpst control payload: %w", err)
	}
	return nil
}

func sslTunnelRequest(session GatewaySession, config TunnelConfig) (string, error) {
	if config.SSLTunnelURL == "" {
		return "", fmt.Errorf("ssl tunnel url: %w", ErrInvalidGPSTHandshake)
	}
	query := url.Values{}
	query.Set("user", session.User)
	query.Set("authcookie", session.AuthCookie.String())
	return fmt.Sprintf("GET %s?%s HTTP/1.1\r\n\r\n", config.SSLTunnelURL, query.Encode()), nil
}

type contextReader struct {
	ctx  context.Context
	conn net.Conn
}

func (r contextReader) Read(buf []byte) (int, error) {
	if err := readContext(r.ctx, r.conn, buf); err != nil {
		return 0, err
	}
	return len(buf), nil
}

func readFullContext(ctx context.Context, conn net.Conn, buf []byte) error {
	stop := make(chan struct{})
	go setDeadlineOnCancel(ctx, conn.SetReadDeadline, stop)
	_, err := io.ReadFull(conn, buf)
	close(stop)
	if resetErr := conn.SetReadDeadline(time.Time{}); resetErr != nil && err == nil {
		return fmt.Errorf("reset read deadline: %w", resetErr)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("read from tunnel: %w", err)
	}
	return nil
}

func readContext(ctx context.Context, conn net.Conn, buf []byte) error {
	return readFullContext(ctx, conn, buf)
}

func writeAllContext(ctx context.Context, conn net.Conn, data []byte) error {
	for len(data) > 0 {
		stop := make(chan struct{})
		go setDeadlineOnCancel(ctx, conn.SetWriteDeadline, stop)
		n, err := conn.Write(data)
		close(stop)
		if resetErr := conn.SetWriteDeadline(time.Time{}); resetErr != nil && err == nil {
			return fmt.Errorf("reset write deadline: %w", resetErr)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			return fmt.Errorf("write to tunnel: %w", err)
		}
		data = data[n:]
	}
	return nil
}

func setDeadlineOnCancel(ctx context.Context, setDeadline func(time.Time) error, stop <-chan struct{}) {
	select {
	case <-ctx.Done():
		if err := setDeadline(time.Now()); err != nil {
			return
		}
	case <-stop:
		return
	}
}
