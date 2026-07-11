package app

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/xiongnemo/globalprotect-socks5/internal/gp"
)

func openDebugLog(path string) (*os.File, []gp.ClientOption, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open debug log: %w", err)
	}
	return file, []gp.ClientOption{gp.WithDebugLog(file)}, nil
}

func closeDebugLog(file *os.File, path string, errp *error) {
	if file == nil {
		return
	}
	if err := file.Close(); err != nil {
		closeErr := fmt.Errorf("close debug log %s: %w", path, err)
		if *errp == nil {
			*errp = closeErr
			return
		}
		*errp = errors.Join(*errp, closeErr)
	}
}
