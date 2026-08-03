package pki

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const maxPassphraseBytes = 1024

func LoadPassphraseFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("CA passphrase file is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect CA passphrase file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("CA passphrase path must be a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return "", errors.New("CA passphrase file must not be accessible by group or others")
	}
	if info.Size() < 1 || info.Size() > maxPassphraseBytes {
		return "", errors.New("CA passphrase file size is invalid")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read CA passphrase file: %w", err)
	}
	value := strings.TrimRight(string(data), "\r\n")
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return "", errors.New("CA passphrase is empty or invalid")
	}
	return value, nil
}
