package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/xiongnemo/globalprotect-socks5/internal/netstatus"
)

const (
	replySucceeded          = byte(0x00)
	replyGeneralErr         = byte(0x01)
	replyNetworkUnreachable = byte(0x03)
	replyHostUnreachable    = byte(0x04)
	replyConnectionRefused  = byte(0x05)
	replyTTLExpired         = byte(0x06)
	replyCommandUnsupported = byte(0x07)
	replyAddressUnsupported = byte(0x08)
)

func dialReplyCode(err error) byte {
	switch netstatus.KindOf(err) {
	case netstatus.Timeout:
		return replyTTLExpired
	case netstatus.NetworkUnreachable:
		return replyNetworkUnreachable
	case netstatus.HostUnreachable:
		return replyHostUnreachable
	case netstatus.ConnectionRefused:
		return replyConnectionRefused
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return replyHostUnreachable
	}
	return replyGeneralErr
}

func writeReply(w io.Writer, code byte, bound net.Addr) error {
	host, port := boundAddress(bound)
	response := []byte{version5, code, 0x00}
	if ip4 := host.To4(); ip4 != nil {
		response = append(response, addrIPv4)
		response = append(response, ip4...)
	} else if ip6 := host.To16(); ip6 != nil {
		response = append(response, addrIPv6)
		response = append(response, ip6...)
	} else {
		response = append(response, addrIPv4, 0, 0, 0, 0)
		port = 0
	}
	response = append(response, byte(port>>8), byte(port))
	if _, err := w.Write(response); err != nil {
		return fmt.Errorf("write socks reply: %w", err)
	}
	return nil
}

func boundAddress(addr net.Addr) (net.IP, uint16) {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr != nil && tcpAddr.Port >= 0 && tcpAddr.Port <= 65535 {
		return tcpAddr.IP, uint16(tcpAddr.Port)
	}
	return net.IPv4zero, 0
}
