package pki

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRealOpenSSLGeneratesVerifiableRSAAndTLCPBundles(t *testing.T) {
	executable := os.Getenv("CERTARIUM_OPENSSL")
	if executable == "" {
		t.Skip("set CERTARIUM_OPENSSL to run real cryptographic integration")
	}
	store := NewStore(t.TempDir())
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(store, CommandRunner{Executable: executable, Timeout: 20 * time.Second})
	ctx := context.Background()
	if err := engine.InitializeAuthorities(ctx, "Certarium Test Lab"); err != nil {
		t.Fatalf("initialize real authorities: %v", err)
	}

	rsaReq := issuanceRequest()
	rsa, err := engine.IssueRSA(ctx, rsaReq)
	if err != nil {
		t.Fatalf("issue real RSA: %v", err)
	}
	assertCertificateText(t, executable, rsa.CertificatePath,
		"Public Key Algorithm: rsaEncryption", "DNS:gateway.example", "IP Address:192.0.2.20", "TLS Web Server Authentication")

	tlcpReq := issuanceRequest()
	tlcpReq.Name = "gateway-tlcp"
	tlcp, err := engine.IssueTLCP(ctx, tlcpReq)
	if err != nil {
		t.Fatalf("issue real TLCP: %v", err)
	}
	assertCertificateText(t, executable, tlcp.Signing.CertificatePath,
		"ASN1 OID: SM2", "Digital Signature", "TLS Web Server Authentication")
	assertCertificateText(t, executable, tlcp.Encryption.CertificatePath,
		"ASN1 OID: SM2", "Key Encipherment", "Data Encipherment", "Key Agreement")
	if bytes.Equal(mustRead(t, tlcp.Signing.KeyPath), mustRead(t, tlcp.Encryption.KeyPath)) {
		t.Fatal("real TLCP issuance reused private key bytes")
	}

	rsaCA := filepath.Join(store.root, "pki", "ca", "rsa", "root-ca.crt")
	sm2CA := filepath.Join(store.root, "pki", "ca", "sm2", "root-ca.crt")
	if err := engine.PublishCRL(ctx, "rsa", []string{rsa.CertificatePath}, nil); err != nil {
		t.Fatalf("publish valid RSA status: %v", err)
	}
	if err := engine.PublishCRL(ctx, "sm2", []string{tlcp.Signing.CertificatePath, tlcp.Encryption.CertificatePath}, nil); err != nil {
		t.Fatalf("publish valid SM2 status: %v", err)
	}
	rsaRequest := makeOCSPRequest(t, executable, rsaCA, rsa.CertificatePath, "")
	assertOCSPStatus(t, engine, executable, "rsa", rsaCA, rsa.CertificatePath, rsaRequest, "good")
	sm2Request := makeOCSPRequest(t, executable, sm2CA, tlcp.Signing.CertificatePath, "")
	assertOCSPStatus(t, engine, executable, "sm2", sm2CA, tlcp.Signing.CertificatePath, sm2Request, "good")
	unknownRequest := makeOCSPRequest(t, executable, rsaCA, "", "2147483647")
	assertOCSPStatus(t, engine, executable, "rsa", rsaCA, "", unknownRequest, "unknown")

	if err := engine.PublishCRL(ctx, "rsa", nil, []string{rsa.CertificatePath}); err != nil {
		t.Fatalf("publish real RSA CRL: %v", err)
	}
	assertCRLText(t, executable, filepath.Join(store.root, "pki", "crl", "rsa.crl.pem"), rsaCA)
	assertOCSPStatus(t, engine, executable, "rsa", rsaCA, rsa.CertificatePath, rsaRequest, "revoked")
	if err := engine.PublishCRL(ctx, "sm2", nil, []string{tlcp.Signing.CertificatePath, tlcp.Encryption.CertificatePath}); err != nil {
		t.Fatalf("publish real SM2 CRL: %v", err)
	}
	assertCRLText(t, executable, filepath.Join(store.root, "pki", "crl", "sm2.crl.pem"), sm2CA)
	assertOCSPStatus(t, engine, executable, "sm2", sm2CA, tlcp.Signing.CertificatePath, sm2Request, "revoked")
}

func makeOCSPRequest(t *testing.T, executable, issuer, cert, serial string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "request.der")
	args := []string{"ocsp", "-issuer", issuer}
	if cert != "" {
		args = append(args, "-cert", cert)
	} else {
		args = append(args, "-serial", serial)
	}
	args = append(args, "-reqout", path, "-no_nonce")
	if output, err := exec.Command(executable, args...).CombinedOutput(); err != nil {
		t.Fatalf("create OCSP request: %v: %s", err, output)
	}
	return mustRead(t, path)
}

func assertOCSPStatus(t *testing.T, engine *Engine, executable, kind, issuer, cert string, request []byte, want string) {
	t.Helper()
	response, err := engine.RespondOCSP(context.Background(), kind, request)
	if err != nil {
		t.Fatalf("generate %s OCSP response: %v", kind, err)
	}
	responsePath := filepath.Join(t.TempDir(), "response.der")
	if err := os.WriteFile(responsePath, response, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"ocsp", "-respin", responsePath, "-issuer", issuer, "-CAfile", issuer, "-text"}
	if cert != "" {
		args = append(args, "-cert", cert)
	}
	output, err := exec.Command(executable, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("verify OCSP response: %v: %s", err, output)
	}
	if !strings.Contains(string(output), want) {
		t.Fatalf("OCSP output missing %q: %s", want, output)
	}
}

func assertCertificateText(t *testing.T, executable, path string, wants ...string) {
	t.Helper()
	cmd := exec.Command(executable, "x509", "-in", path, "-noout", "-text")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect certificate %s: %v: %s", path, err, output)
	}
	for _, want := range wants {
		if !strings.Contains(string(output), want) {
			t.Errorf("certificate %s missing %q", path, want)
		}
	}
}

func assertCRLText(t *testing.T, executable, crlPath, caPath string) {
	t.Helper()
	cmd := exec.Command(executable, "crl", "-in", crlPath, "-noout", "-text", "-verify", "-CAfile", caPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect CRL %s: %v: %s", crlPath, err, output)
	}
	for _, want := range []string{"verify OK", "Revoked Certificates:", "Serial Number:"} {
		if !strings.Contains(string(output), want) {
			t.Errorf("CRL %s missing %q: %s", crlPath, want, output)
		}
	}
}
