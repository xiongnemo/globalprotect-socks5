package gp_test

import (
	"encoding/base64"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_ParsePrelogin_decodesSAMLRequest_whenRedirectMethodReturned(t *testing.T) {
	// Given
	loginURL := "https://idp.example.test/login?SAMLRequest=abc"
	encoded := base64.StdEncoding.EncodeToString([]byte(loginURL))
	body := []byte(`<prelogin-response><saml-auth-method>REDIRECT</saml-auth-method><saml-request>` + encoded + `</saml-request><saml-default-browser>yes</saml-default-browser><region>AU</region></prelogin-response>`)

	// When
	got, err := gp.ParsePrelogin(body)

	// Then
	if err != nil {
		t.Fatalf("ParsePrelogin() error = %v", err)
	}
	if got.SAMLMethod != gp.SAMLRedirect {
		t.Fatalf("SAMLMethod = %q, want %q", got.SAMLMethod, gp.SAMLRedirect)
	}
	if got.SAMLRequest.String() != loginURL {
		t.Fatalf("SAMLRequest = %q, want %q", got.SAMLRequest.String(), loginURL)
	}
	if !got.DefaultBrowser {
		t.Fatal("DefaultBrowser = false, want true")
	}
	if got.Region != "AU" {
		t.Fatalf("Region = %q, want AU", got.Region)
	}
}

func Test_ParsePrelogin_reportsPasswordAuth_whenNoSAMLRequestReturned(t *testing.T) {
	// Given
	body := []byte(`<prelogin-response><status>success</status><auth-method>password</auth-method></prelogin-response>`)

	// When
	got, err := gp.ParsePrelogin(body)

	// Then
	if err != nil {
		t.Fatalf("ParsePrelogin() error = %v", err)
	}
	if got.AuthMode != gp.AuthModePassword {
		t.Fatalf("AuthMode = %q, want %q", got.AuthMode, gp.AuthModePassword)
	}
}
