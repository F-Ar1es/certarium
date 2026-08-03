package pki

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPassphraseFileRequiresPrivateRegularNonemptyFile(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "ca.pass")
	if err := os.WriteFile(good, []byte("correct horse battery staple\n"), 0400); err != nil {
		t.Fatal(err)
	}
	value, err := LoadPassphraseFile(good)
	if err != nil || value != "correct horse battery staple" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	for name, data := range map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"empty": {nil, 0400}, "public": {[]byte("secret"), 0444},
		"large": {make([]byte, 1025), 0400},
	} {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data.data, data.mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPassphraseFile(path); err == nil {
			t.Errorf("%s passphrase accepted", name)
		}
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPassphraseFile(link); err == nil {
		t.Fatal("symlink passphrase accepted")
	}
}
