package socks5_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/socks5"
)

func Test_Server_authenticatesUsernameAndPassword_withoutNoAuthDowngrade(t *testing.T) {
	credentials := &socks5.Credentials{Username: "alice", Password: "correct horse"}
	addr, stop := startConfiguredSocksServer(t, socks5.Config{DialContext: unusedDial, Credentials: credentials})
	defer stop()
	client := dialSocks(t, addr)
	defer client.Close()

	writeAll(t, client, []byte{0x05, 0x02, 0x00, 0x02})
	assertBytes(t, client, []byte{0x05, 0x02})
	writeUserPass(t, client, "alice", "correct horse")
	assertBytes(t, client, []byte{0x01, 0x00})
}

func Test_Server_rejectsInvalidUsernameOrPassword(t *testing.T) {
	credentials := &socks5.Credentials{Username: "alice", Password: "expected"}
	addr, stop := startConfiguredSocksServer(t, socks5.Config{DialContext: unusedDial, Credentials: credentials})
	defer stop()
	client := dialSocks(t, addr)
	defer client.Close()

	writeAll(t, client, []byte{0x05, 0x01, 0x02})
	assertBytes(t, client, []byte{0x05, 0x02})
	writeUserPass(t, client, "alice", "wrong")
	assertBytes(t, client, []byte{0x01, 0x01})
	assertClosed(t, client)
}

func Test_Server_rejectsNoAuth_whenCredentialsConfigured(t *testing.T) {
	credentials := &socks5.Credentials{Username: "alice", Password: "expected"}
	addr, stop := startConfiguredSocksServer(t, socks5.Config{DialContext: unusedDial, Credentials: credentials})
	defer stop()
	client := dialSocks(t, addr)
	defer client.Close()

	writeAll(t, client, []byte{0x05, 0x01, 0x00})
	assertBytes(t, client, []byte{0x05, 0xff})
}

func Test_Server_closesClient_afterHandshakeTimeout(t *testing.T) {
	addr, stop := startConfiguredSocksServer(t, socks5.Config{
		DialContext: unusedDial, HandshakeTimeout: 20 * time.Millisecond,
	})
	defer stop()
	client := dialSocks(t, addr)
	defer client.Close()
	assertClosed(t, client)
}

func Test_Server_rejectsConnectionBeyondConfiguredLimit(t *testing.T) {
	addr, stop := startConfiguredSocksServer(t, socks5.Config{
		DialContext: unusedDial, MaxConnections: 1, HandshakeTimeout: time.Second,
	})
	defer stop()
	first := dialSocks(t, addr)
	defer first.Close()
	second := dialSocks(t, addr)
	defer second.Close()
	assertClosed(t, second)
}

func Test_Server_mapsProtocolAndDialFailuresToRFCReplyCodes(t *testing.T) {
	tests := []struct {
		name string
		dial socks5.DialFunc
		req  []byte
		want byte
	}{
		{name: "command unsupported", dial: unusedDial, req: requestWithHeader(0x02, 0x01), want: 0x07},
		{name: "address unsupported", dial: unusedDial, req: requestWithHeader(0x01, 0x09), want: 0x08},
		{name: "connection refused", dial: errorDial(syscall.ECONNREFUSED), req: ipv4Request(), want: 0x05},
		{name: "network unreachable", dial: errorDial(syscall.ENETUNREACH), req: ipv4Request(), want: 0x03},
		{name: "host unreachable", dial: errorDial(syscall.EHOSTUNREACH), req: ipv4Request(), want: 0x04},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr, stop := startConfiguredSocksServer(t, socks5.Config{DialContext: test.dial})
			defer stop()
			client := dialSocks(t, addr)
			defer client.Close()
			writeAll(t, client, []byte{0x05, 0x01, 0x00})
			assertBytes(t, client, []byte{0x05, 0x00})
			writeAll(t, client, test.req)
			reply := make([]byte, 10)
			readFull(t, client, reply)
			if reply[1] != test.want {
				t.Fatalf("reply code = %#x, want %#x", reply[1], test.want)
			}
		})
	}
}

func Test_Server_mapsConnectTimeoutToTTLExpired(t *testing.T) {
	dial := socks5.DialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	addr, stop := startConfiguredSocksServer(t, socks5.Config{DialContext: dial, ConnectTimeout: 20 * time.Millisecond})
	defer stop()
	client := dialSocks(t, addr)
	defer client.Close()
	writeAll(t, client, []byte{0x05, 0x01, 0x00})
	assertBytes(t, client, []byte{0x05, 0x00})
	writeAll(t, client, ipv4Request())
	reply := make([]byte, 10)
	readFull(t, client, reply)
	if reply[1] != 0x06 {
		t.Fatalf("reply code = %#x, want 0x06", reply[1])
	}
}

func TestServerMapsRealSystemRefusalToConnectionRefused(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target Listen() error = %v", err)
	}
	port := uint16(target.Addr().(*net.TCPAddr).Port)
	if err := target.Close(); err != nil {
		t.Fatalf("target Close() error = %v", err)
	}
	var dialer net.Dialer
	addr, stop := startConfiguredSocksServer(t, socks5.Config{DialContext: dialer.DialContext})
	defer stop()
	client := dialSocks(t, addr)
	defer client.Close()
	writeAll(t, client, []byte{0x05, 0x01, 0x00})
	assertBytes(t, client, []byte{0x05, 0x00})
	writeAll(t, client, ipv4RequestPort(port))
	reply := make([]byte, 10)
	readFull(t, client, reply)
	if reply[1] != 0x05 {
		t.Fatalf("real refusal reply code = %#x, want 0x05", reply[1])
	}
}

func Test_ValidateCredentials_enforcesRFC1929ByteLengths(t *testing.T) {
	if err := socks5.ValidateCredentials(socks5.Credentials{Username: "alice", Password: "secret"}); err != nil {
		t.Fatalf("valid credentials error = %v", err)
	}
	for _, credentials := range []socks5.Credentials{
		{Password: "secret"}, {Username: "alice"},
		{Username: string(make([]byte, 256)), Password: "secret"},
		{Username: "alice", Password: string(make([]byte, 256))},
	} {
		if !errors.Is(socks5.ValidateCredentials(credentials), socks5.ErrInvalidCredentials) {
			t.Fatal("invalid credentials were accepted")
		}
	}
}

func startConfiguredSocksServer(t *testing.T, config socks5.Config) (string, func()) {
	t.Helper()
	server := socks5.NewServer(config)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ctx, listener) }()
	return listener.Addr().String(), func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("Serve() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Serve() did not stop")
		}
	}
}

func dialSocks(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	return conn
}

func writeUserPass(t *testing.T, w io.Writer, username, password string) {
	t.Helper()
	request := []byte{0x01, byte(len(username))}
	request = append(request, username...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	writeAll(t, w, request)
}

func assertClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	_, err := conn.Read(one[:])
	if err == nil {
		t.Fatal("connection remained open")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("connection did not close before deadline: %v", err)
	}
}

func requestWithHeader(command, addressType byte) []byte {
	return []byte{0x05, command, 0x00, addressType}
}

func ipv4Request() []byte {
	return ipv4RequestPort(443)
}

func ipv4RequestPort(targetPort uint16) []byte {
	request := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], targetPort)
	return append(request, port[:]...)
}

func errorDial(err error) socks5.DialFunc {
	return func(context.Context, string, string) (net.Conn, error) { return nil, err }
}
