package socks5

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"slices"
)

const (
	version5          = byte(0x05)
	methodNoAuth      = byte(0x00)
	methodUserPass    = byte(0x02)
	methodUnavailable = byte(0xff)
	userPassVersion   = byte(0x01)
)

var ErrInvalidCredentials = errors.New("socks5: invalid credential configuration")

func ValidateCredentials(credentials Credentials) error {
	usernameLength := len([]byte(credentials.Username))
	passwordLength := len([]byte(credentials.Password))
	if usernameLength < 1 || usernameLength > 255 || passwordLength < 1 || passwordLength > 255 {
		return ErrInvalidCredentials
	}
	return nil
}

func negotiate(conn io.ReadWriter, credentials *Credentials) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read socks greeting: %w", err)
	}
	if header[0] != version5 {
		return fmt.Errorf("unsupported socks version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read socks methods: %w", err)
	}
	selected := methodNoAuth
	if credentials != nil {
		selected = methodUserPass
	}
	if !slices.Contains(methods, selected) {
		if _, err := conn.Write([]byte{version5, methodUnavailable}); err != nil {
			return fmt.Errorf("write auth rejection: %w", err)
		}
		return errors.New("socks5: no supported auth method")
	}
	if _, err := conn.Write([]byte{version5, selected}); err != nil {
		return fmt.Errorf("write greeting response: %w", err)
	}
	if credentials == nil {
		return nil
	}
	return authenticateUserPass(conn, *credentials)
}

func authenticateUserPass(conn io.ReadWriter, expected Credentials) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read socks auth header: %w", err)
	}
	if header[0] != userPassVersion || header[1] == 0 {
		return rejectUserPass(conn)
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("read socks username: %w", err)
	}
	length := make([]byte, 1)
	if _, err := io.ReadFull(conn, length); err != nil {
		return fmt.Errorf("read socks password length: %w", err)
	}
	if length[0] == 0 {
		return rejectUserPass(conn)
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("read socks password: %w", err)
	}
	usernameOK := subtle.ConstantTimeCompare(username, []byte(expected.Username))
	passwordOK := subtle.ConstantTimeCompare(password, []byte(expected.Password))
	if usernameOK&passwordOK != 1 {
		return rejectUserPass(conn)
	}
	if _, err := conn.Write([]byte{userPassVersion, 0x00}); err != nil {
		return fmt.Errorf("write socks auth success: %w", err)
	}
	return nil
}

func rejectUserPass(conn io.Writer) error {
	if _, err := conn.Write([]byte{userPassVersion, 0x01}); err != nil {
		return fmt.Errorf("write socks auth rejection: %w", err)
	}
	return errors.New("socks5: username/password authentication failed")
}
