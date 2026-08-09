package app_test

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xiongnemo/globalprotect-socks5/internal/app"
	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
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

func Test_Run_serveUsesPacketTunnelDialer_whenPortalProvided(t *testing.T) {
	// Given
	html := `<html><body><form method="POST" action="https://idp.example.test/sso"></form></body></html>`
	encoded := base64.StdEncoding.EncodeToString([]byte(html))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/global-protect/prelogin.esp":
			_, _ = w.Write([]byte(`<prelogin-response><saml-auth-method>POST</saml-auth-method><saml-request>` + encoded + `</saml-request><saml-default-browser>yes</saml-default-browser></prelogin-response>`))
		case "/global-protect/getconfig.esp":
			_, _ = w.Write(portalPolicyResponse("http://" + r.Host))
		case "/ssl-vpn/prelogin.esp":
			_, _ = w.Write(gatewaySAMLPreloginResponse())
		case "/ssl-vpn/login.esp":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if got := r.Form.Get("portal-userauthcookie"); got != "portal-cookie" {
				t.Fatalf("portal-userauthcookie = %q, want portal-cookie", got)
			}
			if got := r.Form.Get("portal-prelogonuserauthcookie"); got != "portal-prelogon-cookie" {
				t.Fatalf("portal-prelogonuserauthcookie = %q, want portal-prelogon-cookie", got)
			}
			_, _ = w.Write([]byte(`<jnlp><application-desc>` +
				`<argument></argument>` +
				`<argument>auth-cookie</argument>` +
				`<argument>persistent-cookie</argument>` +
				`<argument>vpn.example.test</argument>` +
				`<argument>alice@example.test</argument>` +
				`<argument>saml</argument>` +
				`<argument>config</argument>` +
				`<argument>EXAMPLE</argument>` +
				`<argument>unused</argument>` +
				`<argument>unused</argument>` +
				`<argument>test-host</argument>` +
				`<argument>unused</argument>` +
				`<argument>tunnel</argument>` +
				`<argument>-1</argument>` +
				`<argument>4100</argument>` +
				`<argument>10.41.0.12</argument>` +
				`</application-desc></jnlp>`))
		case "/ssl-vpn/getconfig.esp":
			_, _ = w.Write([]byte(`<response status="success"><result>` +
				`<ip-address>10.41.0.12</ip-address>` +
				`<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>` +
				`</result></response>`))
		default:
			t.Fatalf("path = %s, want GlobalProtect endpoint", r.URL.Path)
		}
	}))
	defer server.Close()
	preloginCookie, err := gp.NewSecret("pre-cookie")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	stdout := newListenCapture()
	capturer := &fakeAuthCapturer{artifact: gp.AuthArtifact{Kind: gp.ArtifactSAML, Username: "alice@example.test", PreloginCookie: preloginCookie}}
	connector := newRecordingPacketTunnelConnector()
	directDialer := newRecordingDialer()
	t.Cleanup(directDialer.closePeers)
	runner := app.NewRunner(app.IO{Stdout: &stdout, HTTPClient: server.Client(), AuthCapturer: capturer, DialContext: directDialer.DialContext, PacketTunnelConnector: connector})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, []string{"serve", "--listen", "127.0.0.1:0", "--portal", server.URL, "--host-id", "test-host", "--browser", "chrome", "--timeout", "1s"})
	}()
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
	if _, err := conn.Write(connectIPv4Request([4]byte{10, 41, 0, 1}, 443)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	packet := connector.tunnel.waitWrite(t)
	request := connector.wait(t)
	cancel()

	// Then
	if len(packet) == 0 {
		t.Fatal("packet tunnel write was empty")
	}
	if request.Session.User != "alice@example.test" {
		t.Fatalf("connector user = %q, want alice@example.test", request.Session.User)
	}
	if request.Config.IP.String() != "10.41.0.12" {
		t.Fatalf("connector config IP = %s, want 10.41.0.12", request.Config.IP)
	}
	if !capturer.called {
		t.Fatal("auth capturer was not called")
	}
	if capturer.request.Browser != "chrome" {
		t.Fatalf("capturer browser = %q, want chrome", capturer.request.Browser)
	}
	select {
	case <-directDialer.ready:
		t.Fatal("direct dialer was called despite portal-backed serve")
	default:
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
