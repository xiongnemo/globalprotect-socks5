package gp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const callbackPrefix = "globalprotectcallback:"

func ParseAuthArtifact(input string) (AuthArtifact, error) {
	trimmed := strings.TrimSpace(input)
	if payload, ok := strings.CutPrefix(trimmed, callbackPrefix); ok {
		return parseCallback(payload)
	}
	values, err := url.ParseQuery(trimmed)
	if err != nil {
		return AuthArtifact{}, fmt.Errorf("parse auth query: %w", err)
	}
	return artifactFromValues(values)
}

func ParseAuthResponse(headers map[string]string, body string) (AuthArtifact, error) {
	artifact, err := ParseAuthHeaders(headers)
	if err == nil {
		return artifact, nil
	}
	if !errors.Is(err, ErrMissingAuthArtifact) {
		return AuthArtifact{}, err
	}
	return ParseAuthBody(body)
}

func ParseAuthHeaders(headers map[string]string) (AuthArtifact, error) {
	values := url.Values{}
	for name, value := range headers {
		key := strings.ToLower(strings.TrimSpace(name))
		switch key {
		case "saml-username", "prelogin-cookie", "portal-userauthcookie":
			values.Set(key, strings.TrimSpace(value))
		}
	}
	return artifactFromValues(values)
}

func ParseAuthBody(body string) (AuthArtifact, error) {
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "<") {
		return artifactFromHTML(trimmed)
	}
	return ParseAuthArtifact(trimmed)
}

func parseCallback(payload string) (AuthArtifact, error) {
	payload = strings.TrimPrefix(payload, "/")
	if strings.HasPrefix(payload, "cas-as=") {
		values, err := url.ParseQuery(payload)
		if err != nil {
			return AuthArtifact{}, fmt.Errorf("parse cas callback: %w", err)
		}
		return casArtifact(values)
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return AuthArtifact{}, fmt.Errorf("decode callback html: %w", ErrInvalidAuthArtifact)
	}
	return artifactFromHTML(string(decoded))
}

func casArtifact(values url.Values) (AuthArtifact, error) {
	token, err := NewSecret(values.Get("token"))
	if err != nil {
		return AuthArtifact{}, err
	}
	return AuthArtifact{Kind: ArtifactCAS, Username: values.Get("un"), Token: token}, nil
}

func artifactFromValues(values url.Values) (AuthArtifact, error) {
	username := values.Get("saml-username")
	prelogin := values.Get("prelogin-cookie")
	portal := values.Get("portal-userauthcookie")
	if username == "" || prelogin == "" && portal == "" {
		return AuthArtifact{}, ErrMissingAuthArtifact
	}
	artifact := AuthArtifact{Kind: ArtifactSAML, Username: username}
	if prelogin != "" {
		secret, err := NewSecret(prelogin)
		if err != nil {
			return AuthArtifact{}, err
		}
		artifact.PreloginCookie = secret
	}
	if portal != "" {
		secret, err := NewSecret(portal)
		if err != nil {
			return AuthArtifact{}, err
		}
		artifact.PortalUserAuthCookie = secret
	}
	return artifact, nil
}

func artifactFromHTML(html string) (AuthArtifact, error) {
	values := url.Values{}
	for _, key := range []string{"saml-username", "prelogin-cookie", "portal-userauthcookie"} {
		value := tagValue(html, key)
		if value != "" {
			values.Set(key, value)
		}
	}
	artifact, err := artifactFromValues(values)
	if err != nil {
		if errors.Is(err, ErrMissingAuthArtifact) {
			return AuthArtifact{}, fmt.Errorf("parse callback html: %w", err)
		}
		return AuthArtifact{}, err
	}
	return artifact, nil
}

func tagValue(s string, name string) string {
	open := "<" + name + ">"
	close := "</" + name + ">"
	start := strings.Index(s, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(s[start:], close)
	if end < 0 {
		return ""
	}
	return s[start : start+end]
}
