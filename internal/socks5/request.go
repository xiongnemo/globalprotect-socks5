package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	commandConnect = byte(0x01)
	addrIPv4       = byte(0x01)
	addrDomain     = byte(0x03)
	addrIPv6       = byte(0x04)
)

type protocolError struct {
	code byte
	err  error
}

func (e protocolError) Error() string { return e.err.Error() }
func (e protocolError) Unwrap() error { return e.err }

func readConnectTarget(r io.Reader) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", protocolError{replyGeneralErr, fmt.Errorf("read connect header: %w", err)}
	}
	if header[0] != version5 || header[2] != 0x00 {
		return "", protocolError{replyGeneralErr, errors.New("socks5: invalid request header")}
	}
	if header[1] != commandConnect {
		return "", protocolError{replyCommandUnsupported, errors.New("socks5: unsupported command")}
	}
	host, err := readAddress(r, header[3])
	if err != nil {
		return "", err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return "", protocolError{replyGeneralErr, fmt.Errorf("read target port: %w", err)}
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readAddress(r io.Reader, typ byte) (string, error) {
	switch typ {
	case addrIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", protocolError{replyGeneralErr, fmt.Errorf("read ipv4 address: %w", err)}
		}
		return net.IP(buf).String(), nil
	case addrIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", protocolError{replyGeneralErr, fmt.Errorf("read ipv6 address: %w", err)}
		}
		return net.IP(buf).String(), nil
	case addrDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(r, length); err != nil {
			return "", protocolError{replyGeneralErr, fmt.Errorf("read domain length: %w", err)}
		}
		if length[0] == 0 {
			return "", protocolError{replyAddressUnsupported, errors.New("socks5: empty domain address")}
		}
		buf := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", protocolError{replyGeneralErr, fmt.Errorf("read domain address: %w", err)}
		}
		return string(buf), nil
	default:
		return "", protocolError{replyAddressUnsupported, fmt.Errorf("unsupported address type %d", typ)}
	}
}

func replyCode(err error) byte {
	var protocolErr protocolError
	if errors.As(err, &protocolErr) {
		return protocolErr.code
	}
	return replyGeneralErr
}
