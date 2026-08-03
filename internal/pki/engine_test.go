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
		if args[i] == "-out" || args[i] == "-respout" {
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

func TestEncryptedAuthorityCommandsNeverExposePassphraseInArguments(t *testing.T) {
	store := NewStore(t.TempDir())
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	const secret = "argument-secret-canary"
	if err := NewEngineWithPassphrase(store, runner, secret).InitializeAuthorities(context.Background(), "Example Lab"); err != nil {
		t.Fatal(err)
	}
	var encrypted, passin bool
	for _, args := range runner.calls {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, secret) {
			t.Fatalf("passphrase leaked into argv: %v", args)
		}
		if containsArgument(args, "-aes-256-cbc") && containsArgument(args, "env:CERTARIUM_CA_PASSPHRASE") {
			encrypted = true
		}
		if containsArgument(args, "-passin") && containsArgument(args, "env:CERTARIUM_CA_PASSPHRASE") {
			passin = true
		}
	}
	if !encrypted || !passin {
		t.Fatalf("encrypted=%v passin=%v calls=%v", encrypted, passin, runner.calls)
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

func TestPublishCRLUsesPrivateDatabaseAndDoesNotReplaceOnFailure(t *testing.T) {
	for _, failAt := range []int{2, 3} {
		t.Run(fmt.Sprintf("fail-command-%d", failAt), func(t *testing.T) {
			store := initializedStore(t)
			crlDir := filepath.Join(store.root, "pki", "crl")
			if err := os.MkdirAll(crlDir, 0700); err != nil {
				t.Fatal(err)
			}
			published := filepath.Join(crlDir, "rsa.crl.pem")
			if err := os.WriteFile(published, []byte("OLD CRL"), 0644); err != nil {
				t.Fatal(err)
			}
			cert := filepath.Join(t.TempDir(), "server.crt")
			if err := os.WriteFile(cert, []byte("CERT"), 0644); err != nil {
				t.Fatal(err)
			}
			runner := &fakeRunner{failAt: failAt}
			err := NewEngine(store, runner).PublishCRL(context.Background(), "rsa", nil, []string{cert})
			if err == nil {
				t.Fatal("CRL publication succeeded despite crypto failure")
			}
			if got := string(mustRead(t, published)); got != "OLD CRL" {
				t.Fatalf("published CRL changed after failure: %q", got)
			}
			if len(runner.calls) < 2 || runner.calls[0][0] != "ca" || !containsArgument(runner.calls[0], "-valid") || !containsArgument(runner.calls[1], "-revoke") {
				t.Fatalf("unexpected CRL command sequence: %v", runner.calls)
			}
		})
	}
}

func TestRespondOCSPUsesAllowlistedIssuerAndCleansTemporaryFiles(t *testing.T) {
	store := initializedStore(t)
	caDir := filepath.Join(store.root, "pki", "ca", "rsa")
	if err := os.WriteFile(filepath.Join(caDir, "index.txt"), []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	response, err := NewEngine(store, runner).RespondOCSP(context.Background(), "rsa", []byte("DER REQUEST"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(response), "generated:") {
		t.Fatalf("response = %q", response)
	}
	if len(runner.calls) != 1 || runner.calls[0][0] != "ocsp" || !containsArgument(runner.calls[0], "-reqin") || !containsArgument(runner.calls[0], "-respout") {
		t.Fatalf("unexpected OCSP command: %v", runner.calls)
	}
	matches, err := filepath.Glob(filepath.Join(store.root, "pki", ".ocsp-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("OCSP temporary files remain: %v, %v", matches, err)
	}

	before := len(runner.calls)
	if _, err := NewEngine(store, runner).RespondOCSP(context.Background(), "../rsa", []byte("DER")); err == nil {
		t.Fatal("unsafe OCSP issuer accepted")
	}
	if len(runner.calls) != before {
		t.Fatal("crypto invoked for unsafe OCSP issuer")
	}

	sm2Dir := filepath.Join(store.root, "pki", "ca", "sm2")
	if err := os.WriteFile(filepath.Join(sm2Dir, "index.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(store, runner).RespondOCSP(context.Background(), "sm2", []byte("DER")); err != nil {
		t.Fatal(err)
	}
	call := runner.calls[len(runner.calls)-1]
	foundSM2Index := false
	for _, arg := range call {
		if strings.HasSuffix(arg, filepath.Join("sm2", "index.txt")) {
			foundSM2Index = true
		}
	}
	if !foundSM2Index {
		t.Fatalf("SM2 OCSP used wrong issuer index: %v", call)
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
