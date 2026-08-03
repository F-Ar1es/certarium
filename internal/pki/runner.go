package pki

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

var ErrCommandTimeout = errors.New("cryptographic command timed out")

type CommandRunner struct {
	Executable string
	Timeout    time.Duration
	Env        []string
}

func (r CommandRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	if r.Executable == "" {
		return nil, errors.New("cryptographic executable is not configured")
	}
	if r.Timeout <= 0 {
		return nil, errors.New("cryptographic command timeout must be positive")
	}
	timed, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(timed, r.Executable, args...)
	cmd.Env = append(os.Environ(), r.Env...)
	var output cappedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if errors.Is(timed.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		return output.Bytes(), ErrCommandTimeout
	}
	if ctx.Err() != nil {
		return output.Bytes(), ctx.Err()
	}
	if err != nil {
		return output.Bytes(), fmt.Errorf("cryptographic command failed: %w: %s", err, output.String())
	}
	return output.Bytes(), nil
}

const maxCommandOutput = 64 * 1024

type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := maxCommandOutput - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return original, nil
}
