package gp

import (
	"errors"
	"fmt"
)

var ErrGatewayAuthFailed = errors.New("gp: gateway auth failed")

type GatewayAuthError struct {
	StatusCode int
}

func (e *GatewayAuthError) Error() string {
	return fmt.Sprintf("%s (status %d)", ErrGatewayAuthFailed, e.StatusCode)
}

func (e *GatewayAuthError) Is(target error) bool {
	return target == ErrGatewayAuthFailed || target == ErrInvalidAuthArtifact
}
