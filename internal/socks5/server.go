package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	defaultHandshakeTimeout = 10 * time.Second
	defaultConnectTimeout   = 30 * time.Second
	defaultMaxConnections   = 256
)

type DialFunc func(ctx context.Context, network string, address string) (net.Conn, error)

type Credentials struct {
	Username string
	Password string
}

type Config struct {
	DialContext      DialFunc
	Credentials      *Credentials
	HandshakeTimeout time.Duration
	ConnectTimeout   time.Duration
	MaxConnections   int
}

type Server struct {
	dial             DialFunc
	credentials      *Credentials
	handshakeTimeout time.Duration
	connectTimeout   time.Duration
	limit            chan struct{}
	mu               sync.Mutex
	conns            map[net.Conn]struct{}
}

func NewServer(cfg Config) *Server {
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = defaultConnectTimeout
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaultMaxConnections
	}
	var credentials *Credentials
	if cfg.Credentials != nil {
		copied := *cfg.Credentials
		credentials = &copied
	}
	return &Server{
		dial: cfg.DialContext, credentials: credentials,
		handshakeTimeout: cfg.HandshakeTimeout, connectTimeout: cfg.ConnectTimeout,
		limit: make(chan struct{}, cfg.MaxConnections), conns: map[net.Conn]struct{}{},
	}
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			s.closeActive()
		case <-serveDone:
		}
	}()

	var wg sync.WaitGroup
	defer func() {
		s.closeActive()
		wg.Wait()
	}()
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
		if !s.acquire() {
			_ = conn.Close()
			continue
		}
		s.track(conn)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.release()
			defer s.untrack(conn)
			_ = s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) error {
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	if err := client.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		return fmt.Errorf("set socks handshake deadline: %w", err)
	}
	if err := negotiate(client, s.credentials); err != nil {
		return err
	}
	target, err := readConnectTarget(client)
	if err != nil {
		_ = writeReply(client, replyCode(err), nil)
		return err
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear socks handshake deadline: %w", err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, s.connectTimeout)
	defer cancel()
	upstream, err := s.dial(dialCtx, "tcp", target)
	if err != nil {
		_ = writeReply(client, dialReplyCode(err), nil)
		return fmt.Errorf("dial socks target: %w", err)
	}
	defer upstream.Close()
	if err := writeReply(client, replySucceeded, upstream.LocalAddr()); err != nil {
		return err
	}
	return proxy(ctx, client, upstream)
}

func (s *Server) acquire() bool {
	select {
	case s.limit <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) release() { <-s.limit }

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

func proxy(ctx context.Context, client, upstream net.Conn) error {
	errCh := make(chan error, 2)
	go copyConn(errCh, upstream, client)
	go copyConn(errCh, client, upstream)
	for range 2 {
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				_ = client.Close()
				_ = upstream.Close()
				return err
			}
		case <-ctx.Done():
			_ = client.Close()
			_ = upstream.Close()
			return nil
		}
	}
	return nil
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
