package webapp

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"certarium/internal/pki"
)

const manifestName = "manifest.json"

type PKIService struct {
	dataDir string
	store   *pki.Store
	engine  *pki.Engine
	mu      sync.Mutex
}

type bundleManifest struct {
	CertificateRecord
	Files []string `json:"files"`
}

func NewPKIService(dataDir string, store *pki.Store, engine *pki.Engine) *PKIService {
	if store == nil {
		store = pki.NewStore(dataDir)
	}
	return &PKIService{dataDir: dataDir, store: store, engine: engine}
}

func (s *PKIService) Status(context.Context) (Status, error) {
	paths := []string{
		filepath.Join(s.dataDir, "pki", "state.json"),
		filepath.Join(s.dataDir, "pki", "ca", "rsa", "root-ca.crt"),
		filepath.Join(s.dataDir, "pki", "ca", "sm2", "root-ca.crt"),
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return Status{Initialized: false}, nil
		}
		if err != nil {
			return Status{}, fmt.Errorf("inspect PKI status: %w", err)
		}
		if !info.Mode().IsRegular() {
			return Status{Initialized: false}, nil
		}
	}
	return Status{Initialized: true}, nil
}

func (s *PKIService) Initialize(ctx context.Context, organization string) error {
	if s.engine == nil {
		return errors.New("PKI engine is unavailable")
	}
	if err := s.store.Initialize(); err != nil {
		if errors.Is(err, pki.ErrAlreadyInitialized) {
			return ErrConflict
		}
		return fmt.Errorf("initialize PKI state: %w", err)
	}
	if err := s.engine.InitializeAuthorities(ctx, organization); err != nil {
		_ = os.RemoveAll(filepath.Join(s.dataDir, "pki"))
		return mapPKIError(err)
	}
	return nil
}

func (s *PKIService) Issue(ctx context.Context, kind string, input IssueRequest) (CertificateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return CertificateRecord{}, errors.New("PKI engine is unavailable")
	}
	req, err := toPKIRequest(input)
	if err != nil {
		return CertificateRecord{}, err
	}
	record := CertificateRecord{
		ID: input.Name, Kind: kind, State: "valid", CommonName: input.CommonName,
		DNSNames:    append([]string(nil), input.DNSNames...),
		IPAddresses: append([]string(nil), input.IPAddresses...), ValidDays: input.ValidDays,
	}
	now := time.Now().UTC()
	record.IssuedAt = now.Format(time.RFC3339)
	record.ExpiresAt = now.Add(time.Duration(input.ValidDays) * 24 * time.Hour).Format(time.RFC3339)
	manifest := bundleManifest{CertificateRecord: record}
	switch kind {
	case "rsa":
		bundle, issueErr := s.engine.IssueRSA(ctx, req)
		if issueErr != nil {
			return CertificateRecord{}, mapPKIError(issueErr)
		}
		manifest.Files = []string{filepath.Base(bundle.CertificatePath), filepath.Base(bundle.KeyPath)}
		record.Serials = []uint64{bundle.Serial}
		record.Purpose = "TLS Web Server Authentication"
	case "tlcp":
		bundle, issueErr := s.engine.IssueTLCP(ctx, req)
		if issueErr != nil {
			return CertificateRecord{}, mapPKIError(issueErr)
		}
		manifest.Files = []string{
			filepath.Base(bundle.Signing.CertificatePath), filepath.Base(bundle.Signing.KeyPath),
			filepath.Base(bundle.Encryption.CertificatePath), filepath.Base(bundle.Encryption.KeyPath),
		}
		record.Serials = []uint64{bundle.Signing.Serial, bundle.Encryption.Serial}
		record.Purpose = "TLCP Signing and Encryption"
	default:
		return CertificateRecord{}, ErrInvalid
	}
	manifest.CertificateRecord = record
	if err := writeManifest(filepath.Join(s.dataDir, "pki", "issued", input.Name, manifestName), manifest); err != nil {
		return CertificateRecord{}, err
	}
	if err := s.refreshIssuer(ctx, kind, ""); err != nil {
		return CertificateRecord{}, err
	}
	return record, nil
}

func (s *PKIService) Revoke(ctx context.Context, id string) (CertificateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil || !safeRouteSegment(id) {
		return CertificateRecord{}, ErrFileNotAllowed
	}
	issued := filepath.Join(s.dataDir, "pki", "issued")
	targetPath := filepath.Join(issued, id, manifestName)
	target, err := readManifest(targetPath)
	if err != nil || target.ID != id {
		return CertificateRecord{}, ErrFileNotAllowed
	}
	if target.State == "revoked" {
		return target.CertificateRecord, nil
	}
	if target.Kind != "rsa" && target.Kind != "tlcp" {
		return CertificateRecord{}, ErrInvalid
	}
	if err := s.refreshIssuer(ctx, target.Kind, id); err != nil {
		return CertificateRecord{}, err
	}
	target.State = "revoked"
	if err := writeManifest(targetPath, target); err != nil {
		return CertificateRecord{}, err
	}
	return target.CertificateRecord, nil
}

func (s *PKIService) refreshIssuer(ctx context.Context, bundleKind, revokeID string) error {
	caKind := "rsa"
	if bundleKind == "tlcp" {
		caKind = "sm2"
	} else if bundleKind != "rsa" {
		return ErrInvalid
	}
	issued := filepath.Join(s.dataDir, "pki", "issued")
	entries, err := os.ReadDir(issued)
	if err != nil {
		return fmt.Errorf("list certificate status inventory: %w", err)
	}
	var validCerts, revokedCerts []string
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		manifest, readErr := readManifest(filepath.Join(issued, entry.Name(), manifestName))
		if readErr != nil || manifest.Kind != bundleKind {
			continue
		}
		state := manifest.State
		if manifest.ID == revokeID {
			state = "revoked"
		}
		for _, name := range manifest.Files {
			if filepath.Ext(name) != ".crt" || !safeRouteSegment(name) {
				continue
			}
			path := filepath.Join(issued, manifest.ID, name)
			if state == "revoked" {
				revokedCerts = append(revokedCerts, path)
			} else {
				validCerts = append(validCerts, path)
			}
		}
	}
	if err := s.engine.PublishCRL(ctx, caKind, validCerts, revokedCerts); err != nil {
		return mapPKIError(err)
	}
	return nil
}

func (s *PKIService) CRL(_ context.Context, kind string) (Download, error) {
	if kind != "rsa" && kind != "sm2" {
		return Download{}, ErrFileNotAllowed
	}
	name := kind + ".crl.pem"
	path := filepath.Join(s.dataDir, "pki", "crl", name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Download{}, ErrFileNotAllowed
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Download{}, ErrFileNotAllowed
	}
	return Download{Name: name, ContentType: "application/pkix-crl", Data: data}, nil
}

func (s *PKIService) OCSP(ctx context.Context, kind string, request []byte) ([]byte, error) {
	if s.engine == nil || (kind != "rsa" && kind != "sm2") {
		return nil, ErrInvalid
	}
	response, err := s.engine.RespondOCSP(ctx, kind, request)
	if err != nil {
		return nil, mapPKIError(err)
	}
	return response, nil
}

func (s *PKIService) List(context.Context) ([]CertificateRecord, error) {
	issued := filepath.Join(s.dataDir, "pki", "issued")
	entries, err := os.ReadDir(issued)
	if errors.Is(err, os.ErrNotExist) {
		return []CertificateRecord{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list issued certificates: %w", err)
	}
	records := make([]CertificateRecord, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		manifest, err := readManifest(filepath.Join(issued, entry.Name(), manifestName))
		if err != nil || manifest.ID != entry.Name() {
			continue
		}
		records = append(records, manifest.CertificateRecord)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func (s *PKIService) Download(_ context.Context, id, name string) (Download, error) {
	if !safeRouteSegment(id) || !safeRouteSegment(name) || name == manifestName {
		return Download{}, ErrFileNotAllowed
	}
	bundleDir := filepath.Join(s.dataDir, "pki", "issued", id)
	manifest, err := readManifest(filepath.Join(bundleDir, manifestName))
	if err != nil || manifest.ID != id || !containsString(manifest.Files, name) {
		return Download{}, ErrFileNotAllowed
	}
	path := filepath.Join(bundleDir, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Download{}, ErrFileNotAllowed
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Download{}, ErrFileNotAllowed
	}
	private := filepath.Ext(name) == ".key"
	contentType := "application/x-pem-file"
	if private {
		contentType = "application/octet-stream"
	}
	return Download{Name: name, ContentType: contentType, Data: data, Private: private}, nil
}

func (s *PKIService) Bundle(_ context.Context, id string) (Download, error) {
	if !safeRouteSegment(id) {
		return Download{}, ErrFileNotAllowed
	}
	dir := filepath.Join(s.dataDir, "pki", "issued", id)
	manifest, err := readManifest(filepath.Join(dir, manifestName))
	if err != nil || manifest.ID != id {
		return Download{}, ErrFileNotAllowed
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, name := range manifest.Files {
		if !safeRouteSegment(name) {
			writer.Close()
			return Download{}, ErrFileNotAllowed
		}
		file := filepath.Join(dir, name)
		info, err := os.Lstat(file)
		if err != nil || !info.Mode().IsRegular() {
			writer.Close()
			return Download{}, ErrFileNotAllowed
		}
		data, err := os.ReadFile(file)
		if err != nil {
			writer.Close()
			return Download{}, ErrFileNotAllowed
		}
		entry, err := writer.Create(name)
		if err != nil {
			writer.Close()
			return Download{}, err
		}
		if _, err := entry.Write(data); err != nil {
			writer.Close()
			return Download{}, err
		}
	}
	if err := writer.Close(); err != nil {
		return Download{}, err
	}
	return Download{Name: id + ".zip", ContentType: "application/zip", Data: buffer.Bytes(), Private: true}, nil
}

func (s *PKIService) RootCA(_ context.Context, kind string) (Download, error) {
	if kind != "rsa" && kind != "sm2" {
		return Download{}, ErrFileNotAllowed
	}
	file := filepath.Join(s.dataDir, "pki", "ca", kind, "root-ca.crt")
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() {
		return Download{}, ErrFileNotAllowed
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return Download{}, ErrFileNotAllowed
	}
	return Download{Name: kind + "-root-ca.crt", ContentType: "application/x-pem-file", Data: data}, nil
}

func toPKIRequest(input IssueRequest) (pki.Request, error) {
	ips := make([]net.IP, 0, len(input.IPAddresses))
	for _, raw := range input.IPAddresses {
		ip := net.ParseIP(raw)
		if ip == nil {
			return pki.Request{}, ErrInvalid
		}
		ips = append(ips, ip)
	}
	req := pki.Request{Name: input.Name, CommonName: input.CommonName, DNSNames: input.DNSNames, IPAddresses: ips, ValidDays: input.ValidDays}
	if err := pki.ValidateRequest(req); err != nil {
		return pki.Request{}, ErrInvalid
	}
	return req, nil
}

func mapPKIError(err error) error {
	if errors.Is(err, pki.ErrCommandTimeout) {
		return ErrCryptoTimeout
	}
	if strings.Contains(err.Error(), "already exist") {
		return ErrConflict
	}
	return ErrCryptoFailure
}

func writeManifest(path string, manifest bundleManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode certificate manifest: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".manifest-*.tmp")
	if err != nil {
		return fmt.Errorf("create certificate manifest: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return fmt.Errorf("secure certificate manifest: %w", err)
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		temp.Close()
		return fmt.Errorf("write certificate manifest: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync certificate manifest: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close certificate manifest: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("publish certificate manifest: %w", err)
	}
	return nil
}

func readManifest(path string) (bundleManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return bundleManifest{}, err
	}
	var manifest bundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return bundleManifest{}, err
	}
	return manifest, nil
}

func safeRouteSegment(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsAny(value, "\x00/\\")
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
