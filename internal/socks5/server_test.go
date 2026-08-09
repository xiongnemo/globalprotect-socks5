package socks5_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
)

func Test_Server_proxiesTCPConnect_whenNoAuthClientConnects(t *testing.T) {
	// Given
	echoAddr := startEchoServer(t)
	dialer := socks5.DialFunc(func(ctx context.Context, network string, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	})
	server := socks5.NewServer(socks5.Config{DialContext: dialer})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("Serve() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Serve() did not stop within 1s")
		}
	})

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	// When
	writeAll(t, conn, []byte{0x05, 0x01, 0x00})
	assertBytes(t, conn, []byte{0x05, 0x00})
	writeAll(t, conn, connectRequest(t, echoAddr))
	reply := make([]byte, 10)
	readFull(t, conn, reply)
	if reply[1] != 0x00 {
		t.Fatalf("CONNECT reply status = %#x, want 0", reply[1])
	}
	if binary.BigEndian.Uint16(reply[8:10]) == 0 {
		t.Fatalf("CONNECT BND.PORT = 0, want upstream local port")
	}
	writeAll(t, conn, []byte("ping"))

	// Then
	buf := make([]byte, len("echo:ping"))
	readFull(t, conn, buf)
	if string(buf) != "echo:ping" {
		t.Fatalf("proxied response = %q, want echo:ping", string(buf))
	}
}

func Test_Server_repliesNoAcceptableMethods_whenClientDoesNotOfferNoAuth(t *testing.T) {
	// Given
	addr, stop := startSocksServer(t, unusedDial)
	defer stop()
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	// When
	writeAll(t, client, []byte{0x05, 0x01, 0x02})

	// Then
	assertBytes(t, client, []byte{0x05, 0xff})
}

func Test_Server_rejectsConnectRequest_whenReservedByteIsNonZero(t *testing.T) {
	// Given
	addr, stop := startSocksServer(t, unusedDial)
	defer stop()
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	// When
	writeAll(t, client, []byte{0x05, 0x01, 0x00})
	assertBytes(t, client, []byte{0x05, 0x00})
	writeAll(t, client, []byte{0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0, 80})

	// Then
	reply := make([]byte, 10)
	readFull(t, client, reply)
	if reply[1] == 0x00 {
		t.Fatalf("CONNECT reply status = %#x, want non-zero", reply[1])
	}
}

func Test_Server_Serve_stops_whenContextCancelledWithIdleClient(t *testing.T) {
	// Given
	server := socks5.NewServer(socks5.Config{DialContext: unusedDial})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ctx, listener) }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	// When
	cancel()

	// Then
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop with idle client after context cancellation")
	}
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				_, _ = c.Write([]byte("echo:" + string(buf)))
			}(conn)
		}
	}()
	return listener.Addr().String()
}

func startSocksServer(t *testing.T, dial socks5.DialFunc) (string, func()) {
	t.Helper()
	server := socks5.NewServer(socks5.Config{DialContext: dial})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ctx, listener) }()
	stop := func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("Serve() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Serve() did not stop within 1s")
		}
	}
	return listener.Addr().String(), stop
}

func connectRequest(t *testing.T, target string) []byte {
	t.Helper()
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatalf("parse port %q: %v", portText, err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(req, p[:]...)
}

func writeAll(t *testing.T, w io.Writer, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
}

func assertBytes(t *testing.T, r io.Reader, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	readFull(t, r, got)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bytes = %#v, want %#v", got, want)
		}
	}
}

func readFull(t *testing.T, r io.Reader, buf []byte) {
	t.Helper()
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
}

func unusedDial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unused dial")
}
