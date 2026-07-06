package gp_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func Test_ParseAuthArtifact_returnsCASToken_whenGlobalProtectCallbackCAS(t *testing.T) {
	// Given
	input := "globalprotectcallback:cas-as=1&un=alice&token=secret-token"

	// When
	got, err := gp.ParseAuthArtifact(input)

	// Then
	if err != nil {
		t.Fatalf("ParseAuthArtifact() error = %v", err)
	}
	if got.Kind != gp.ArtifactCAS {
		t.Fatalf("Kind = %q, want %q", got.Kind, gp.ArtifactCAS)
	}
	if got.Username != "alice" {
		t.Fatalf("Username = %q, want alice", got.Username)
	}
	if got.Token.String() != "secret-token" {
		t.Fatalf("Token = %q, want secret-token", got.Token.String())
	}
}

func Test_ParseAuthArtifact_returnsPreloginCookie_whenCallbackContainsBase64HTML(t *testing.T) {
	// Given
	html := `<html><saml-auth-status>1</saml-auth-status><saml-username>bob</saml-username><prelogin-cookie>pre-cookie</prelogin-cookie></html>`
	input := "globalprotectcallback:" + base64.StdEncoding.EncodeToString([]byte(html))

	// When
	got, err := gp.ParseAuthArtifact(input)

	// Then
	if err != nil {
		t.Fatalf("ParseAuthArtifact() error = %v", err)
	}
	if got.Kind != gp.ArtifactSAML {
		t.Fatalf("Kind = %q, want %q", got.Kind, gp.ArtifactSAML)
	}
	if got.Username != "bob" {
		t.Fatalf("Username = %q, want bob", got.Username)
	}
	if got.PreloginCookie.String() != "pre-cookie" {
		t.Fatalf("PreloginCookie = %q, want pre-cookie", got.PreloginCookie.String())
	}
}

func Test_ParseAuthArtifact_rejectsInput_withoutBearerArtifact(t *testing.T) {
	// Given
	input := "saml-username=alice&saml-auth-status=1"

	// When
	_, err := gp.ParseAuthArtifact(input)

	// Then
	if !errors.Is(err, gp.ErrMissingAuthArtifact) {
		t.Fatalf("error = %v, want ErrMissingAuthArtifact", err)
	}
}
