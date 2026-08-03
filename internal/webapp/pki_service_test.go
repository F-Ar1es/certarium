package webapp

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"certarium/internal/pki"
)

func TestPKIServiceBundleAndRootCAExposeOnlyDeclaredPublicFiles(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "pki", "issued", "gateway")
	ca := filepath.Join(root, "pki", "ca", "rsa")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ca, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, manifestName), []byte(`{"id":"gateway","kind":"rsa","files":["server.crt","server.key"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"server.crt": "CERT", "server.key": "KEY", "hidden.key": "HIDDEN"} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ca, "root-ca.crt"), []byte("ROOT"), 0644); err != nil {
		t.Fatal(err)
	}
	service := NewPKIService(root, nil, nil)
	download, err := service.Bundle(context.Background(), "gateway")
	if err != nil {
		t.Fatal(err)
	}
	if !download.Private || download.ContentType != "application/zip" {
		t.Fatalf("bundle metadata = %#v", download)
	}
	reader, err := zip.NewReader(bytes.NewReader(download.Data), int64(len(download.Data)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range reader.File {
		names = append(names, file.Name)
	}
	if len(names) != 2 || names[0] != "server.crt" || names[1] != "server.key" {
		t.Fatalf("bundle names = %v", names)
	}
	rootDownload, err := service.RootCA(context.Background(), "rsa")
	if err != nil || string(rootDownload.Data) != "ROOT" || rootDownload.Private {
		t.Fatalf("root download=%#v err=%v", rootDownload, err)
	}
	if _, err := service.RootCA(context.Background(), "../rsa"); !errors.Is(err, ErrFileNotAllowed) {
		t.Fatalf("unsafe root kind error=%v", err)
	}
}

func TestPKIServiceBundleRejectsAllowlistedSymlink(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "pki", "issued", "gateway")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, manifestName), []byte(`{"id":"gateway","files":["server.key"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(bundle, "server.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPKIService(root, nil, nil).Bundle(context.Background(), "gateway"); !errors.Is(err, ErrFileNotAllowed) {
		t.Fatalf("symlink bundle error=%v", err)
	}
}

type crlFakeRunner struct {
	mu    sync.Mutex
	calls int
	args  [][]string
}

func (r *crlFakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.args = append(r.args, append([]string(nil), args...))
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-out" {
			if err := os.WriteFile(args[i+1], []byte("CRL"), 0644); err != nil {
				return nil, err
			}
		}
	}
	return []byte("OK"), nil
}

func TestTLCPRevocationIncludesBothCertificates(t *testing.T) {
	root := t.TempDir()
	store := pki.NewStore(root)
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	caDir := filepath.Join(root, "pki", "ca", "sm2")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"root-ca.crt": "CA", "root-ca.key": "KEY", "crlnumber": "1000\n"} {
		if err := os.WriteFile(filepath.Join(caDir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	bundle := filepath.Join(root, "pki", "issued", "gateway")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"id":"gateway","kind":"tlcp","state":"valid","files":["server-sign.crt","server-sign.key","server-enc.crt","server-enc.key"]}`
	if err := os.WriteFile(filepath.Join(bundle, manifestName), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server-sign.crt", "server-enc.crt"} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte("CERT"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &crlFakeRunner{}
	service := NewPKIService(root, store, pki.NewEngine(store, runner))
	if _, err := service.Revoke(context.Background(), "gateway"); err != nil {
		t.Fatal(err)
	}
	revokes := 0
	for _, args := range runner.args {
		for _, arg := range args {
			if arg == "-revoke" {
				revokes++
			}
		}
	}
	if revokes != 2 {
		t.Fatalf("TLCP revoke commands = %d, want 2: %v", revokes, runner.args)
	}
}

func TestPKIServiceDownloadUsesManifestAllowlist(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "pki", "issued", "gateway")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"id":"gateway","kind":"rsa","files":["server-rsa.crt","server-rsa.key"]}`
	if err := os.WriteFile(filepath.Join(bundle, manifestName), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "server-rsa.crt"), []byte("CERT"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "server-rsa.key"), []byte("KEY"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "root-ca.key"), []byte("CA KEY"), 0600); err != nil {
		t.Fatal(err)
	}
	service := NewPKIService(root, nil, nil)

	got, err := service.Download(context.Background(), "gateway", "server-rsa.key")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Private || string(got.Data) != "KEY" {
		t.Fatalf("download = %#v", got)
	}
	for _, name := range []string{"../state.json", "root-ca.key", manifestName, "server-rsa.csr", "server-rsa.crt/extra"} {
		if _, err := service.Download(context.Background(), "gateway", name); !errors.Is(err, ErrFileNotAllowed) {
			t.Errorf("download %q error = %v, want ErrFileNotAllowed", name, err)
		}
	}
}

func TestPKIServiceRejectsSymlinkEvenWhenNameIsAllowlisted(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "pki", "issued", "gateway")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := `{"id":"gateway","kind":"rsa","files":["server-rsa.key"]}`
	if err := os.WriteFile(filepath.Join(bundle, manifestName), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(bundle, "server-rsa.key")); err != nil {
		t.Fatal(err)
	}
	service := NewPKIService(root, nil, nil)
	if _, err := service.Download(context.Background(), "gateway", "server-rsa.key"); !errors.Is(err, ErrFileNotAllowed) {
		t.Fatalf("symlink download error = %v", err)
	}
}

func TestPKIServiceListIgnoresMalformedAndTemporaryEntries(t *testing.T) {
	root := t.TempDir()
	issued := filepath.Join(root, "pki", "issued")
	if err := os.MkdirAll(filepath.Join(issued, "good"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(issued, ".temporary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(issued, "broken"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(issued, "good", manifestName), []byte(`{"id":"good","kind":"rsa"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(issued, "broken", manifestName), []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	records, err := NewPKIService(root, nil, nil).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ID != "good" {
		t.Fatalf("records = %#v", records)
	}
}

func TestConcurrentRepeatedRevocationIsIdempotent(t *testing.T) {
	root := t.TempDir()
	store := pki.NewStore(root)
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	caDir := filepath.Join(root, "pki", "ca", "rsa")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"root-ca.crt": "CA", "root-ca.key": "KEY", "crlnumber": "1000\n"} {
		if err := os.WriteFile(filepath.Join(caDir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	bundle := filepath.Join(root, "pki", "issued", "gateway")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"id":"gateway","kind":"rsa","state":"valid","files":["server-rsa.crt","server-rsa.key"]}`
	if err := os.WriteFile(filepath.Join(bundle, manifestName), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "server-rsa.crt"), []byte("CERT"), 0644); err != nil {
		t.Fatal(err)
	}
	runner := &crlFakeRunner{}
	service := NewPKIService(root, store, pki.NewEngine(store, runner))

	const workers = 12
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, err := service.Revoke(context.Background(), "gateway")
			if err == nil && record.State != "revoked" {
				err = errors.New("revocation did not return revoked state")
			}
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if runner.calls != 4 {
		t.Fatalf("crypto calls = %d, want one four-command CRL publication", runner.calls)
	}
}

func TestIssuanceRefreshesOnlineStatusIndex(t *testing.T) {
	root := t.TempDir()
	store := pki.NewStore(root)
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	caDir := filepath.Join(root, "pki", "ca", "rsa")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"root-ca.crt": "CA", "root-ca.key": "KEY", "crlnumber": "1000\n"} {
		if err := os.WriteFile(filepath.Join(caDir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &crlFakeRunner{}
	service := NewPKIService(root, store, pki.NewEngine(store, runner))
	_, err := service.Issue(context.Background(), "rsa", IssueRequest{
		Name: "online", CommonName: "online.test", DNSNames: []string{"online.test"}, ValidDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	registered := false
	for _, args := range runner.args {
		for _, arg := range args {
			if arg == "-valid" {
				registered = true
			}
		}
	}
	if !registered {
		t.Fatal("issued certificate was not registered for online status")
	}
}
