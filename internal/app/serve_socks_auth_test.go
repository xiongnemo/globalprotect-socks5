package app_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
)

func Test_Run_serveWiresSOCKSAuthenticationWithoutLeakingPassword(t *testing.T) {
	const (
		username = "proxy-user"
		password = "SOCKS_PASSWORD_CANARY_4D27"
	)
	stdout := newListenCapture()
	var stderr, applicationLog bytes.Buffer
	runner := app.NewRunner(app.IO{
		Stdout: &stdout, Stderr: &stderr, LogWriter: &applicationLog,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, []string{
			"serve", "--listen", "127.0.0.1:0",
			"--socks-username", username, "--socks-password", password,
			"--handshake-timeout", "2s", "--connect-timeout", "2s", "--max-connections", "4",
		})
	}()
	conn, err := net.Dial("tcp", stdout.wait(t))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	writeSOCKSBytes(t, conn, []byte{0x05, 0x02, 0x00, 0x02})
	assertSOCKSBytes(t, conn, []byte{0x05, 0x02})
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	writeSOCKSBytes(t, conn, auth)
	assertSOCKSBytes(t, conn, []byte{0x01, 0x00})
	cancel()

	select {
	case runErr := <-errCh:
		if runErr != nil {
			if strings.Contains(runErr.Error(), password) {
				t.Fatal("serve error leaked SOCKS password")
			}
			t.Fatalf("Run() error = %v", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("serve did not stop after cancellation")
	}
	stdout.mu.Lock()
	output := stdout.text
	stdout.mu.Unlock()
	if strings.Contains(output, password) || strings.Contains(stderr.String(), password) || strings.Contains(applicationLog.String(), password) {
		t.Fatal("SOCKS password leaked to command output or application log")
	}
}

func Test_Run_rejectsInvalidSOCKSCredentialsWithoutLeakingPassword(t *testing.T) {
	password := "INVALID_SOCKS_PASSWORD_CANARY_91B7" + strings.Repeat("x", 256)
	var stdout, stderr, applicationLog bytes.Buffer
	runner := app.NewRunner(app.IO{
		Stdout: &stdout, Stderr: &stderr, LogWriter: &applicationLog,
	})
	err := runner.Run(context.Background(), []string{
		"serve", "--socks-username", "proxy-user", "--socks-password", password,
	})
	if err == nil {
		t.Fatal("Run() error = nil, want invalid credentials")
	}
	for _, output := range []string{err.Error(), stdout.String(), stderr.String(), applicationLog.String()} {
		if strings.Contains(output, password) {
			t.Fatal("invalid SOCKS password leaked to error, output, or application log")
		}
	}
}

func writeSOCKSBytes(t *testing.T, writer io.Writer, value []byte) {
	t.Helper()
	if _, err := writer.Write(value); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
}

func assertSOCKSBytes(t *testing.T, reader io.Reader, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("SOCKS response = %#v, want %#v", got, want)
	}
}
