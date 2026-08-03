package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAppendProducesConcurrentParseablePrivateJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log := New(path)
	const workers = 24
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := log.Append(Record{Time: time.Now().UTC(), RequestID: "request\nvalue", RemoteAddr: "127.0.0.1", Action: "issue", Resource: "rsa/test", Outcome: "success"}); err != nil {
				t.Errorf("append: %v", err)
			}
		}()
	}
	wg.Wait()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytesLines(data)
	if len(lines) != workers {
		t.Fatalf("lines = %d, want %d", len(lines), workers)
	}
	for _, line := range lines {
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		if record.RequestID != "request\nvalue" || record.Outcome != "success" {
			t.Fatalf("record = %#v", record)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("audit mode = %v, err=%v", info.Mode().Perm(), err)
	}
}

func TestAppendRejectsSymlinkAndSecretFieldsDoNotExist(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "audit.jsonl")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := New(path).Append(Record{Action: "initialize", Outcome: "failure"}); err == nil {
		t.Fatal("audit symlink accepted")
	}
	data, _ := json.Marshal(Record{})
	for _, forbidden := range []string{"password", "passphrase", "private_key", "body"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("audit schema contains forbidden field %q: %s", forbidden, data)
		}
	}
}

func bytesLines(data []byte) [][]byte {
	var lines [][]byte
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}
