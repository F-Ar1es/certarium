package pki

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var ErrNotImplemented = errors.New("not implemented")
var ErrAlreadyInitialized = errors.New("PKI state already initialized")

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Request struct {
	Name        string
	CommonName  string
	DNSNames    []string
	IPAddresses []net.IP
	ValidDays   int
}

type Store struct {
	root string
	mu   sync.Mutex
}

func NewStore(root string) *Store { return &Store{root: root} }

func ValidateRequest(req Request) error {
	if !safeName.MatchString(req.Name) || req.Name == "." || req.Name == ".." {
		return errors.New("name must be 1-64 safe filename characters")
	}
	if req.CommonName == "" || len(req.CommonName) > 253 || strings.IndexAny(req.CommonName, "\x00\r\n/\\=") >= 0 {
		return errors.New("common name is empty, too long, or unsafe")
	}
	for _, name := range req.DNSNames {
		if !validDNSName(name) {
			return fmt.Errorf("DNS name %q is invalid", name)
		}
	}
	for _, ip := range req.IPAddresses {
		if ip == nil || ip.To16() == nil {
			return errors.New("IP address is invalid")
		}
	}
	if req.ValidDays < 1 || req.ValidDays > 825 {
		return errors.New("validity must be between 1 and 825 days")
	}
	return nil
}

func (s *Store) Initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pkiDir := filepath.Join(s.root, "pki")
	statePath := filepath.Join(pkiDir, "state.json")
	if _, err := os.Lstat(statePath); err == nil {
		return ErrAlreadyInitialized
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect state: %w", err)
	}
	if err := os.MkdirAll(pkiDir, 0700); err != nil {
		return fmt.Errorf("create PKI directory: %w", err)
	}
	if err := os.Chmod(pkiDir, 0700); err != nil {
		return fmt.Errorf("secure PKI directory: %w", err)
	}
	return writeStateAtomic(statePath, state{Version: 1, NextSerial: 1}, true)
}

func (s *Store) NextSerial() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	statePath := filepath.Join(s.root, "pki", "state.json")
	current, err := readState(statePath)
	if err != nil {
		return 0, err
	}
	serial := current.NextSerial
	if serial == 0 || serial == ^uint64(0) {
		return 0, errors.New("serial counter is invalid or exhausted")
	}
	current.NextSerial++
	if err := writeStateAtomic(statePath, current, false); err != nil {
		return 0, err
	}
	return serial, nil
}

type state struct {
	Version    int    `json:"version"`
	NextSerial uint64 `json:"next_serial"`
}

func readState(path string) (state, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return state{}, fmt.Errorf("read state: %w", err)
	}
	var value state
	if err := json.Unmarshal(data, &value); err != nil {
		return state{}, fmt.Errorf("decode state: %w", err)
	}
	if value.Version != 1 {
		return state{}, fmt.Errorf("unsupported state version %d", value.Version)
	}
	return value, nil
}

func writeStateAtomic(path string, value state, exclusive bool) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return fmt.Errorf("secure temporary state: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write temporary state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync temporary state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary state: %w", err)
	}
	if exclusive {
		if _, err := os.Lstat(path); err == nil {
			return ErrAlreadyInitialized
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect destination state: %w", err)
		}
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("publish state: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func validDNSName(name string) bool {
	if name == "" || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	if strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
