package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedBackupRoundTripAndWrongPassword(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	config := filepath.Join(root, "config")
	mustWrite(t, filepath.Join(data, "pki", "ca", "rsa", "root-ca.key"), []byte("PRIVATE-KEY-CANARY"), 0600)
	mustWrite(t, filepath.Join(data, "audit.jsonl"), []byte("{\"action\":\"issue\"}\n"), 0600)
	mustWrite(t, filepath.Join(config, "ca.pass"), []byte("ca-secret\n"), 0400)
	artifact := filepath.Join(root, "backup.certarium")
	if err := Create(data, config, artifact, "backup-password"); err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("PRIVATE-KEY-CANARY"), []byte("ca-secret"), []byte("audit.jsonl")} {
		if bytes.Contains(encrypted, secret) {
			t.Fatalf("encrypted artifact contains plaintext %q", secret)
		}
	}
	if err := Restore(artifact, filepath.Join(root, "wrong-data"), filepath.Join(root, "wrong-config"), "wrong-password", false); err == nil {
		t.Fatal("wrong password restored backup")
	}
	restoredData := filepath.Join(root, "restored-data")
	restoredConfig := filepath.Join(root, "restored-config")
	if err := Restore(artifact, restoredData, restoredConfig, "backup-password", false); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(restoredData, "pki", "ca", "rsa", "root-ca.key"), "PRIVATE-KEY-CANARY", 0600)
	assertFile(t, filepath.Join(restoredData, "audit.jsonl"), "{\"action\":\"issue\"}\n", 0600)
	assertFile(t, filepath.Join(restoredConfig, "ca.pass"), "ca-secret\n", 0400)
}

func TestBackupRejectsSymlinkAndRestoreProtectsExistingState(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	config := filepath.Join(root, "config")
	mustWrite(t, filepath.Join(data, "state"), []byte("original"), 0600)
	mustWrite(t, filepath.Join(config, "settings"), []byte("config"), 0600)
	link := filepath.Join(data, "link")
	if err := os.Symlink(filepath.Join(data, "state"), link); err != nil {
		t.Fatal(err)
	}
	if err := Create(data, config, filepath.Join(root, "bad"), "password"); err == nil {
		t.Fatal("backup accepted symlink")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(root, "good")
	if err := Create(data, config, artifact, "password"); err != nil {
		t.Fatal(err)
	}
	targetData := filepath.Join(root, "target-data")
	targetConfig := filepath.Join(root, "target-config")
	mustWrite(t, filepath.Join(targetData, "keep"), []byte("do-not-overwrite"), 0600)
	if err := Restore(artifact, targetData, targetConfig, "password", false); err == nil {
		t.Fatal("restore overwrote existing state without replace")
	}
	assertFile(t, filepath.Join(targetData, "keep"), "do-not-overwrite", 0600)
}

func TestRestoreRejectsCorruption(t *testing.T) {
	root := t.TempDir()
	data, config := filepath.Join(root, "data"), filepath.Join(root, "config")
	mustWrite(t, filepath.Join(data, "state"), []byte("state"), 0600)
	mustWrite(t, filepath.Join(config, "config"), []byte("config"), 0600)
	artifact := filepath.Join(root, "backup")
	if err := Create(data, config, artifact, "password"); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(artifact)
	content[len(content)-1] ^= 0xff
	corrupt := filepath.Join(root, "corrupt")
	if err := os.WriteFile(corrupt, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(corrupt, filepath.Join(root, "out-data"), filepath.Join(root, "out-config"), "password", false); err == nil {
		t.Fatal("corrupt backup restored")
	}
}

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path, want string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != want {
		t.Fatalf("read %s = %q, err=%v", path, data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != mode {
		t.Fatalf("mode %s = %v, err=%v", path, info.Mode().Perm(), err)
	}
}
