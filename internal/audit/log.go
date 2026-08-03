package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Record struct {
	Time       time.Time `json:"time"`
	RequestID  string    `json:"request_id"`
	RemoteAddr string    `json:"remote_addr"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	Outcome    string    `json:"outcome"`
	ErrorCode  string    `json:"error_code,omitempty"`
}

type Log struct {
	path string
	mu   sync.Mutex
}

func New(path string) *Log { return &Log{path: path} }

// Ready verifies that the required audit destination can be opened securely
// before a state-changing operation is allowed to run.
func (l *Log) Ready() error {
	if l == nil || l.path == "" {
		return errors.New("audit log is not configured")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	file, err := l.open()
	if err != nil {
		return err
	}
	return file.Close()
}

func (l *Log) Append(record Record) error {
	if l == nil || l.path == "" {
		return errors.New("audit log is not configured")
	}
	if record.Time.IsZero() {
		record.Time = time.Now().UTC()
	} else {
		record.Time = record.Time.UTC()
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode audit record: %w", err)
	}
	data = append(data, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	file, err := l.open()
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("append audit record: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync audit log: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}
	return nil
}

func (l *Log) open() (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(l.path), 0700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	if info, err := os.Lstat(l.path); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("audit destination is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect audit log: %w", err)
	}
	file, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure audit log: %w", err)
	}
	return file, nil
}
