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
	"sync"
	"time"
)

var (
	ErrInvalidGPSTFrame     = errors.New("gp: invalid gpst frame")
	ErrInvalidGPSTHandshake = errors.New("gp: invalid gpst handshake")
	ErrGPSTDeadPeer         = errors.New("gp: gpst dead peer")
	ErrGPSTRekeyDue         = errors.New("gp: gpst rekey due")
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
	conn      net.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	writeLock chan struct{}
	stateMu   sync.Mutex
	lastRx    time.Time
	lastTx    time.Time
	dpdSent   time.Time
	terminal  error
	options   gpstRuntimeOptions
	started   time.Time
	stopOnce  sync.Once
	closeErr  error
	wg        sync.WaitGroup
}

type gpstRuntimeOptions struct {
	handshakeTimeout time.Duration
	dpdInterval      time.Duration
	dpdTimeout       time.Duration
	writeTimeout     time.Duration
	rekeyAfter       time.Duration
}

func defaultGPSTRuntimeOptions() gpstRuntimeOptions {
	return gpstRuntimeOptions{
		handshakeTimeout: 30 * time.Second,
		dpdInterval:      10 * time.Second,
		dpdTimeout:       20 * time.Second,
		writeTimeout:     10 * time.Second,
	}
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

func (t *SSLPacketTunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	reader := contextReader{ctx: ctx, conn: t.conn}
	for {
		header := make([]byte, gpstHeaderLen)
		if err := readFullContext(ctx, t.conn, header); err != nil {
			if stopped := t.stoppedError(ctx); stopped != nil {
				return nil, stopped
			}
			return nil, fmt.Errorf("read gpst header: %w", err)
		}
		t.markReceived()
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
	if err := t.writeFrame(ctx, frame); err != nil {
		return fmt.Errorf("write gpst packet: %w", err)
	}
	return nil
}

func (t *SSLPacketTunnel) Close() error {
	t.stop(nil)
	t.wg.Wait()
	return t.closeErr
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
