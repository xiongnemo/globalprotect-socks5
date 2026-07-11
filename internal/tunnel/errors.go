package tunnel

import (
	"errors"
)

var (
	ErrInvalidConfig      = errors.New("tunnel: invalid config")
	ErrUnsupportedNetwork = errors.New("tunnel: unsupported network")
	ErrIPv6Unsupported    = errors.New("tunnel: ipv6 unsupported")
	ErrNoIPv4Address      = errors.New("tunnel: no ipv4 address")
)

type netstackError struct {
	message string
}

func (e netstackError) Error() string {
	return e.message
}
