package pki

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls  [][]string
	failAt int
}

func (r *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	if r.failAt > 0 && len(r.calls) == r.failAt {
		return nil, errors.New("injected crypto failure")
	}
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-out" {
			if err := os.WriteFile(args[i+1], []byte("generated:"+args[i+1]+"\n"), 0644); err != nil {
				return nil, err
			}
		}
	}
	return []byte("OK"), nil
}

func issuanceRequest() Request {
	return Request{
		Name: "gateway", CommonName: "gateway.example",
		DNSNames:    []string{"gateway.example"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.20")}, ValidDays: 397,
	}
}

func initializedStore(t *testing.T) *Store {
	t.Helper()
	store := NewStore(t.TempDir())
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	for _, ca := range []string{"rsa", "sm2"} {
		dir := filepath.Join(store.root, "pki", "ca", ca)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"root-ca.crt", "root-ca.key"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("test CA"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return store
}

func TestInitializeAuthoritiesCreatesIndependentRSAAndSM2Roots(t *testing.T) {
	store := NewStore(t.TempDir())
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	engine := NewEngine(store, runner)
	if err := engine.InitializeAuthorities(context.Background(), "Example Lab"); err != nil {
		t.Fatalf("initialize authorities: %v", err)
	}
	keys := []string{
		filepath.Join(store.root, "pki", "ca", "rsa", "root-ca.key"),
		filepath.Join(store.root, "pki", "ca", "sm2", "root-ca.key"),
	}
	for _, key := range keys {
		info, err := os.Stat(key)
		if err != nil {
			t.Fatalf("root key %q: %v", key, err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("root key mode %04o, want 0600", got)
		}
	}
	if string(mustRead(t, keys[0])) == string(mustRead(t, keys[1])) {
		t.Fatal("RSA and SM2 root keys are identical")
	}
	if err := engine.InitializeAuthorities(context.Background(), "Example Lab"); err == nil {
		t.Fatal("authority reinitialization succeeded")
	}
}

func TestInitializeAuthoritiesRejectsUnsafeOrganizationBeforeCrypto(t *testing.T) {
	store := NewStore(t.TempDir())
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	err := NewEngine(store, runner).InitializeAuthorities(context.Background(), "Lab\nCN=attacker")
	if err == nil {
		t.Fatal("unsafe organization accepted")
	}
	if len(runner.calls) != 0 {
		t.Fatal("crypto invoked for unsafe organization")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestIssueRSAAtomicallyPublishesPrivateBundle(t *testing.T) {
	store := initializedStore(t)
	runner := &fakeRunner{}
	bundle, err := NewEngine(store, runner).IssueRSA(context.Background(), issuanceRequest())
	if err != nil {
		t.Fatalf("issue RSA: %v", err)
	}
	if bundle.Serial == 0 {
		t.Fatal("zero serial")
	}
	for _, path := range []string{bundle.CertificatePath, bundle.KeyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("published file %q: %v", path, err)
		}
		if !strings.Contains(path, filepath.Join("issued", "gateway")) {
			t.Fatalf("unsafe publication path %q", path)
		}
	}
	info, err := os.Stat(bundle.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("key mode %04o, want 0600", got)
	}
	if len(runner.calls) < 4 {
		t.Fatalf("got %d crypto calls, want at least 4", len(runner.calls))
	}
}

func TestIssueTLCPUsesDistinctKeysSerialsAndProfiles(t *testing.T) {
	store := initializedStore(t)
	runner := &fakeRunner{}
	bundle, err := NewEngine(store, runner).IssueTLCP(context.Background(), issuanceRequest())
	if err != nil {
		t.Fatalf("issue TLCP: %v", err)
	}
	if bundle.Signing.Serial == bundle.Encryption.Serial {
		t.Fatal("TLCP certificates reused a serial")
	}
	if bundle.Signing.KeyPath == bundle.Encryption.KeyPath {
		t.Fatal("TLCP certificates reused a private key")
	}
	signConfig, err := os.ReadFile(filepath.Join(filepath.Dir(bundle.Signing.KeyPath), "sign-ext.cnf"))
	if err != nil {
		t.Fatal(err)
	}
	encConfig, err := os.ReadFile(filepath.Join(filepath.Dir(bundle.Encryption.KeyPath), "enc-ext.cnf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(signConfig), "digitalSignature") || strings.Contains(string(signConfig), "keyEncipherment") {
		t.Fatalf("wrong signing profile:\n%s", signConfig)
	}
	if !strings.Contains(string(encConfig), "keyAgreement") || strings.Contains(string(encConfig), "digitalSignature") {
		t.Fatalf("wrong encryption profile:\n%s", encConfig)
	}
}

func TestIssueFailureDoesNotPublishPartialBundle(t *testing.T) {
	store := initializedStore(t)
	runner := &fakeRunner{failAt: 2}
	_, err := NewEngine(store, runner).IssueRSA(context.Background(), issuanceRequest())
	if err == nil || !strings.Contains(err.Error(), "injected crypto failure") {
		t.Fatalf("error = %v, want injected failure", err)
	}
	final := filepath.Join(store.root, "pki", "issued", "gateway")
	if _, statErr := os.Stat(final); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial bundle published at %s", final)
	}
	matches, globErr := filepath.Glob(filepath.Join(store.root, "pki", "issued", ".gateway-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary bundles left behind: %v", matches)
	}
}

func TestIssueRefusesExistingNameWithoutCryptoCalls(t *testing.T) {
	store := initializedStore(t)
	final := filepath.Join(store.root, "pki", "issued", "gateway")
	if err := os.MkdirAll(final, 0700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	_, err := NewEngine(store, runner).IssueRSA(context.Background(), issuanceRequest())
	if err == nil {
		t.Fatal("existing bundle overwritten")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("crypto invoked before overwrite refusal: %s", fmt.Sprint(runner.calls))
	}
}

func TestEveryReqCommandUsesExplicitConfig(t *testing.T) {
	store := NewStore(t.TempDir())
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	engine := NewEngine(store, runner)
	if err := engine.InitializeAuthorities(context.Background(), "Example Lab"); err != nil {
		t.Fatal(err)
	}
	req := issuanceRequest()
	if _, err := engine.IssueRSA(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	req.Name = "gateway-tlcp"
	if _, err := engine.IssueTLCP(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, args := range runner.calls {
		if len(args) == 0 || args[0] != "req" {
			continue
		}
		count++
		if !containsArgument(args, "-config") {
			t.Errorf("req command has no explicit -config: %v", args)
		}
	}
	if count != 5 {
		t.Fatalf("checked %d req commands, want 5", count)
	}
}

func containsArgument(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
