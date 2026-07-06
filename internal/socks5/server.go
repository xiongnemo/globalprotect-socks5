package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
)

const (
	version5        = byte(0x05)
	methodNoAuth    = byte(0x00)
	commandConnect  = byte(0x01)
	addrIPv4        = byte(0x01)
	addrDomain      = byte(0x03)
	addrIPv6        = byte(0x04)
	replySucceeded  = byte(0x00)
	replyGeneralErr = byte(0x01)
)

type DialFunc func(ctx context.Context, network string, address string) (net.Conn, error)

type Config struct {
	DialContext DialFunc
}

type Server struct {
	dial  DialFunc
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func NewServer(cfg Config) *Server {
	return &Server{dial: cfg.DialContext, conns: map[net.Conn]struct{}{}}
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		s.closeActive()
	}()
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept socks connection: %w", err)
		}
		if ctx.Err() != nil {
			_ = conn.Close()
			return nil
		}
		s.track(conn)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.untrack(conn)
			_ = s.handle(ctx, conn)
		}()
	}
}

func (s *Server) track(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[conn] = struct{}{}
}

func (s *Server) untrack(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
	_ = conn.Close()
}

func (s *Server) closeActive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.conns {
		_ = conn.Close()
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-done:
		}
	}()
	defer close(done)
	if err := negotiateNoAuth(client); err != nil {
		return err
	}
	target, err := readConnectTarget(client)
	if err != nil {
		_ = writeReply(client, replyGeneralErr)
		return err
	}
	upstream, err := s.dial(ctx, "tcp", target)
	if err != nil {
		_ = writeReply(client, replyGeneralErr)
		return fmt.Errorf("dial target %s: %w", target, err)
	}
	defer upstream.Close()
	if err := writeReply(client, replySucceeded); err != nil {
		return err
	}
	return proxy(ctx, client, upstream)
}

func negotiateNoAuth(conn io.ReadWriter) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read socks greeting: %w", err)
	}
	if header[0] != version5 {
		return fmt.Errorf("unsupported socks version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read socks methods: %w", err)
	}
	if slices.Contains(methods, methodNoAuth) {
		if _, err := conn.Write([]byte{version5, methodNoAuth}); err != nil {
			return fmt.Errorf("write greeting response: %w", err)
		}
		return nil
	}
	if _, err := conn.Write([]byte{version5, 0xff}); err != nil {
		return fmt.Errorf("write auth rejection: %w", err)
	}
	return errors.New("socks5: no supported auth method")
}

func readConnectTarget(r io.Reader) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", fmt.Errorf("read connect header: %w", err)
	}
	if header[0] != version5 || header[1] != commandConnect || header[2] != 0x00 {
		return "", errors.New("socks5: unsupported request")
	}
	host, err := readAddress(r, header[3])
	if err != nil {
		return "", err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return "", fmt.Errorf("read target port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readAddress(r io.Reader, typ byte) (string, error) {
	switch typ {
	case addrIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("read ipv4 address: %w", err)
		}
		return net.IP(buf).String(), nil
	case addrIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("read ipv6 address: %w", err)
		}
		return net.IP(buf).String(), nil
	case addrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("read domain address: %w", err)
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", typ)
	}
}

func writeReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{version5, code, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return fmt.Errorf("write socks reply: %w", err)
	}
	return nil
}

func proxy(ctx context.Context, client net.Conn, upstream net.Conn) error {
	errCh := make(chan error, 2)
	go copyConn(errCh, upstream, client)
	go copyConn(errCh, client, upstream)
	var firstErr error
	for range 2 {
		select {
		case err := <-errCh:
			if err != nil && firstErr == nil && !errors.Is(err, net.ErrClosed) {
				firstErr = err
			}
		case <-ctx.Done():
			_ = client.Close()
			_ = upstream.Close()
			return nil
		}
	}
	return firstErr
}

func copyConn(errCh chan<- error, dst net.Conn, src net.Conn) {
	_, err := io.Copy(dst, src)
	if closer, ok := dst.(interface{ CloseWrite() error }); ok {
		if closeErr := closer.CloseWrite(); err == nil {
			err = closeErr
		}
	} else {
		_ = dst.Close()
	}
	errCh <- err
}
