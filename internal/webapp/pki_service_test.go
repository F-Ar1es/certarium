package webapp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
