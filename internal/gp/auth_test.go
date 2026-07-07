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

func Test_ParseAuthArtifact_returnsCASToken_whenGlobalProtectCallbackHasLeadingSlash(t *testing.T) {
	// Given
	input := "globalprotectcallback:/cas-as=1&un=alice&token=secret-token"

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

func Test_ParseAuthArtifact_returnsPreloginCookie_whenBase64CallbackHasLeadingSlash(t *testing.T) {
	// Given
	html := `<html><saml-auth-status>1</saml-auth-status><saml-username>bob</saml-username><prelogin-cookie>pre-cookie</prelogin-cookie></html>`
	input := "globalprotectcallback:/" + base64.StdEncoding.EncodeToString([]byte(html))

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

func Test_ParseAuthHeaders_returnsPreloginCookie_whenACSHeadersContainSAMLFields(t *testing.T) {
	// Given
	headers := map[string]string{
		"Saml-Username":    "alice@example.test",
		"Prelogin-Cookie":  "pre-cookie",
		"Saml-Auth-Status": "1",
	}

	// When
	got, err := gp.ParseAuthHeaders(headers)

	// Then
	if err != nil {
		t.Fatalf("ParseAuthHeaders() error = %v", err)
	}
	if got.Kind != gp.ArtifactSAML {
		t.Fatalf("Kind = %q, want %q", got.Kind, gp.ArtifactSAML)
	}
	if got.Username != "alice@example.test" {
		t.Fatalf("Username = %q, want alice@example.test", got.Username)
	}
	if got.PreloginCookie.String() != "pre-cookie" {
		t.Fatalf("PreloginCookie = %q, want pre-cookie", got.PreloginCookie.String())
	}
}

func Test_ParseAuthHeaders_returnsPortalCookie_whenHeaderCaseVaries(t *testing.T) {
	// Given
	headers := map[string]string{
		"saml-username":          "alice@example.test",
		"portal-userauthcookie":  "portal-cookie",
		"saml-auth-status":       "1",
		"irrelevant-header-name": "ignored",
	}

	// When
	got, err := gp.ParseAuthHeaders(headers)

	// Then
	if err != nil {
		t.Fatalf("ParseAuthHeaders() error = %v", err)
	}
	if got.PortalUserAuthCookie.String() != "portal-cookie" {
		t.Fatalf("PortalUserAuthCookie = %q, want portal-cookie", got.PortalUserAuthCookie.String())
	}
}

func Test_ParseAuthBody_returnsPreloginCookie_whenACSBodyContainsSAMLTags(t *testing.T) {
	// Given
	body := `<html><saml-auth-status>1</saml-auth-status><saml-username>alice@example.test</saml-username><prelogin-cookie>pre-cookie</prelogin-cookie></html>`

	// When
	got, err := gp.ParseAuthBody(body)

	// Then
	if err != nil {
		t.Fatalf("ParseAuthBody() error = %v", err)
	}
	if got.Username != "alice@example.test" {
		t.Fatalf("Username = %q, want alice@example.test", got.Username)
	}
	if got.PreloginCookie.String() != "pre-cookie" {
		t.Fatalf("PreloginCookie = %q, want pre-cookie", got.PreloginCookie.String())
	}
}

func Test_ParseAuthBody_returnsPreloginCookie_whenACSBodyContainsQueryValues(t *testing.T) {
	// Given
	body := "saml-username=alice%40example.test&prelogin-cookie=pre-cookie"

	// When
	got, err := gp.ParseAuthBody(body)

	// Then
	if err != nil {
		t.Fatalf("ParseAuthBody() error = %v", err)
	}
	if got.Username != "alice@example.test" {
		t.Fatalf("Username = %q, want alice@example.test", got.Username)
	}
	if got.PreloginCookie.String() != "pre-cookie" {
		t.Fatalf("PreloginCookie = %q, want pre-cookie", got.PreloginCookie.String())
	}
}

func Test_ParseAuthResponse_returnsBodyArtifact_whenHeadersDoNotContainBearerArtifact(t *testing.T) {
	// Given
	headers := map[string]string{"Content-Type": "text/html"}
	body := `<saml-username>alice@example.test</saml-username><prelogin-cookie>pre-cookie</prelogin-cookie>`

	// When
	got, err := gp.ParseAuthResponse(headers, body)

	// Then
	if err != nil {
		t.Fatalf("ParseAuthResponse() error = %v", err)
	}
	if got.PreloginCookie.String() != "pre-cookie" {
		t.Fatalf("PreloginCookie = %q, want pre-cookie", got.PreloginCookie.String())
	}
}

func Test_ParseAuthResponse_returnsHeaderArtifact_beforeBodyArtifact(t *testing.T) {
	// Given
	headers := map[string]string{
		"Saml-Username":   "header@example.test",
		"Prelogin-Cookie": "header-cookie",
	}
	body := `<saml-username>body@example.test</saml-username><prelogin-cookie>body-cookie</prelogin-cookie>`

	// When
	got, err := gp.ParseAuthResponse(headers, body)

	// Then
	if err != nil {
		t.Fatalf("ParseAuthResponse() error = %v", err)
	}
	if got.Username != "header@example.test" {
		t.Fatalf("Username = %q, want header@example.test", got.Username)
	}
	if got.PreloginCookie.String() != "header-cookie" {
		t.Fatalf("PreloginCookie = %q, want header-cookie", got.PreloginCookie.String())
	}
}

func Test_ParseAuthResponse_rejectsInput_withoutBearerArtifact(t *testing.T) {
	// Given
	headers := map[string]string{"Saml-Username": "alice@example.test"}
	body := `<saml-auth-status>1</saml-auth-status>`

	// When
	_, err := gp.ParseAuthResponse(headers, body)

	// Then
	if !errors.Is(err, gp.ErrMissingAuthArtifact) {
		t.Fatalf("error = %v, want ErrMissingAuthArtifact", err)
	}
}
