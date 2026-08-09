package gp

import "errors"

var (
	ErrMissingAuthArtifact = errors.New("gp: missing auth artifact")
	ErrInvalidAuthArtifact = errors.New("gp: invalid auth artifact")
	ErrInvalidPortalURL    = errors.New("gp: invalid portal url")
	ErrInvalidPrelogin     = errors.New("gp: invalid prelogin response")
)

type ArtifactKind string

const (
	ArtifactCAS  ArtifactKind = "cas"
	ArtifactSAML ArtifactKind = "saml"
)

type AuthMode string

const (
	AuthModePassword AuthMode = "password"
	AuthModeSAML     AuthMode = "saml"
)

type SAMLMethod string

const (
	SAMLPost     SAMLMethod = "POST"
	SAMLRedirect SAMLMethod = "REDIRECT"
)

type ClientOS string

const (
	ClientOSLinux ClientOS = "Linux"
)

type Secret struct {
	raw string
}

func NewSecret(raw string) (Secret, error) {
	if raw == "" {
		return Secret{}, ErrMissingAuthArtifact
	}
	return Secret{raw: raw}, nil
}

func (s Secret) String() string {
	return s.raw
}

type SAMLRequest struct {
	raw string
}

func NewSAMLRequest(raw string) (SAMLRequest, error) {
	if raw == "" {
		return SAMLRequest{}, ErrInvalidPrelogin
	}
	return SAMLRequest{raw: raw}, nil
}

func (r SAMLRequest) String() string {
	return r.raw
}

type AuthArtifact struct {
	Kind                         ArtifactKind
	Username                     string
	Token                        Secret
	PreloginCookie               Secret
	PortalUserAuthCookie         Secret
	PortalPrelogonUserAuthCookie Secret
}

type Prelogin struct {
	AuthMode       AuthMode
	SAMLMethod     SAMLMethod
	SAMLRequest    SAMLRequest
	DefaultBrowser bool
	Region         string
}

type ClientProfile struct {
	HostID   string
	Computer string
	ClientOS ClientOS
}
