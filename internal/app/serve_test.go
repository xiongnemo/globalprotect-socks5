package app_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
)

func Test_Run_serveUsesConfiguredDialer_whenConnectRequestArrives(t *testing.T) {
	// Given
	stdout := newListenCapture()
	dialer := newRecordingDialer()
	t.Cleanup(dialer.closePeers)
	runner := app.NewRunner(app.IO{Stdout: &stdout, DialContext: dialer.DialContext})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runner.Run(ctx, []string{"serve", "--listen", "127.0.0.1:0"}) }()
	conn, err := net.Dial("tcp", stdout.wait(t))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	response := make([]byte, 2)
	if _, err := conn.Read(response); err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// When
	if _, err := conn.Write(connectRequest("example.test", 443)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	reply := make([]byte, 10)
	if _, err := conn.Read(reply); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	network, address := dialer.wait(t)
	cancel()

	// Then
	if network != "tcp" {
		t.Fatalf("network = %q, want tcp", network)
	}
	if address != "example.test:443" {
		t.Fatalf("address = %q, want example.test:443", address)
	}
	if reply[1] != 0x00 {
		t.Fatalf("SOCKS reply = %#v, want success", reply)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve command did not stop after cancellation")
	}
}
