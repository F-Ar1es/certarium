package pki

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestInitializeCreatesPrivateStateAndRejectsOverwrite(t *testing.T) {
	root := t.TempDir()
	store := NewStore(root)
	if err := store.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	statePath := filepath.Join(root, "pki", "state.json")
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("state file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("state mode = %04o, want 0600", got)
	}
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(); err == nil {
		t.Fatal("second initialization succeeded, want refusal")
	}
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("second initialization altered existing state")
	}
}

func TestNextSerialIsUniqueUnderConcurrencyAndPersists(t *testing.T) {
	root := t.TempDir()
	store := NewStore(root)
	if err := store.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	const workers = 32
	serials := make(chan uint64, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serial, err := store.NextSerial()
			if err != nil {
				errs <- err
				return
			}
			serials <- serial
		}()
	}
	wg.Wait()
	close(serials)
	close(errs)
	for err := range errs {
		t.Fatalf("next serial: %v", err)
	}
	seen := map[uint64]bool{}
	for serial := range serials {
		if seen[serial] {
			t.Fatalf("duplicate serial %d", serial)
		}
		seen[serial] = true
	}
	if len(seen) != workers {
		t.Fatalf("got %d serials, want %d", len(seen), workers)
	}

	reopened := NewStore(root)
	next, err := reopened.NextSerial()
	if err != nil {
		t.Fatalf("reopened next serial: %v", err)
	}
	if seen[next] {
		t.Fatalf("reopened store reused serial %d", next)
	}
}
