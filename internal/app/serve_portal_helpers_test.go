package app_test

import (
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func parsedForm(t *testing.T, r *http.Request) url.Values {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm() error = %v", err)
	}
	return r.Form
}

func waitForm(t *testing.T, forms <-chan url.Values) url.Values {
	t.Helper()
	select {
	case form := <-forms:
		return form
	case <-time.After(time.Second):
		t.Fatal("gateway login was not called")
		return nil
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

func dialServeListener(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	return conn
}

func writeSOCKSGreeting(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	response := make([]byte, 2)
	if _, err := conn.Read(response); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
}

func assertPortalConfigCalled(t *testing.T, called <-chan struct{}) {
	t.Helper()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("portal getconfig was not called")
	}
}
