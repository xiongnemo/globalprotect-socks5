package netstatus

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

type Kind uint8

const (
	Unknown Kind = iota
	Timeout
	NetworkUnreachable
	HostUnreachable
	ConnectionRefused
)

var (
	ErrTimeout            = errors.New("network timeout")
	ErrNetworkUnreachable = errors.New("network unreachable")
	ErrHostUnreachable    = errors.New("host unreachable")
	ErrConnectionRefused  = errors.New("connection refused")
)

const (
	wsaNetworkUnreachable = syscall.Errno(10051)
	wsaTimedOut           = syscall.Errno(10060)
	wsaConnectionRefused  = syscall.Errno(10061)
	wsaHostUnreachable    = syscall.Errno(10065)
)

func KindOf(err error) Kind {
	switch {
	case err == nil:
		return Unknown
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, ErrTimeout), errors.Is(err, syscall.ETIMEDOUT):
		return Timeout
	case errors.Is(err, ErrNetworkUnreachable), errors.Is(err, syscall.ENETUNREACH):
		return NetworkUnreachable
	case errors.Is(err, ErrHostUnreachable), errors.Is(err, syscall.EHOSTUNREACH):
		return HostUnreachable
	case errors.Is(err, ErrConnectionRefused), errors.Is(err, syscall.ECONNREFUSED):
		return ConnectionRefused
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case wsaTimedOut:
			return Timeout
		case wsaNetworkUnreachable:
			return NetworkUnreachable
		case wsaHostUnreachable:
			return HostUnreachable
		case wsaConnectionRefused:
			return ConnectionRefused
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return Timeout
	}
	return Unknown
}

func Wrap(kind Kind, err error) error {
	if err == nil {
		return nil
	}
	sentinel := sentinelFor(kind)
	if sentinel == nil || errors.Is(err, sentinel) {
		return err
	}
	return fmt.Errorf("%w: %w", sentinel, err)
}

func sentinelFor(kind Kind) error {
	switch kind {
	case Timeout:
		return ErrTimeout
	case NetworkUnreachable:
		return ErrNetworkUnreachable
	case HostUnreachable:
		return ErrHostUnreachable
	case ConnectionRefused:
		return ErrConnectionRefused
	default:
		return nil
	}
}
