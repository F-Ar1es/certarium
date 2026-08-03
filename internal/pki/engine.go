package pki

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type Runner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type Engine struct {
	store  *Store
	runner Runner
	mu     sync.Mutex
}

type Bundle struct {
	CertificatePath string
	KeyPath         string
	Serial          uint64
}

type TLCPBundle struct {
	Signing    Bundle
	Encryption Bundle
}

func NewEngine(store *Store, runner Runner) *Engine {
	return &Engine{store: store, runner: runner}
}

func (e *Engine) InitializeAuthorities(ctx context.Context, organization string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if organization == "" || len(organization) > 64 || strings.IndexAny(organization, "\x00\r\n/\\=") >= 0 {
		return errors.New("organization is empty, too long, or unsafe")
	}
	pkiDir := filepath.Join(e.store.root, "pki")
	if _, err := readState(filepath.Join(pkiDir, "state.json")); err != nil {
		return fmt.Errorf("initialize state before authorities: %w", err)
	}
	final := filepath.Join(pkiDir, "ca")
	if _, err := os.Lstat(final); err == nil {
		return errors.New("certificate authorities already exist")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect certificate authorities: %w", err)
	}
	temp, err := os.MkdirTemp(pkiDir, ".ca-*")
	if err != nil {
		return fmt.Errorf("create temporary CA directory: %w", err)
	}
	defer os.RemoveAll(temp)
	if err := os.Chmod(temp, 0700); err != nil {
		return fmt.Errorf("secure temporary CA directory: %w", err)
	}
	rsaDir := filepath.Join(temp, "rsa")
	sm2Dir := filepath.Join(temp, "sm2")
	for _, dir := range []string{rsaDir, sm2Dir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			return fmt.Errorf("create CA algorithm directory: %w", err)
		}
		for name, content := range map[string]string{
			"index.txt": "", "index.txt.attr": "unique_subject = no\n", "crlnumber": "1000\n",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
				return fmt.Errorf("initialize CA database: %w", err)
			}
		}
	}
	rsaKey, rsaCert := filepath.Join(rsaDir, "root-ca.key"), filepath.Join(rsaDir, "root-ca.crt")
	sm2Key, sm2Cert := filepath.Join(sm2Dir, "root-ca.key"), filepath.Join(sm2Dir, "root-ca.crt")
	caConfig := filepath.Join(temp, "ca.cnf")
	if err := os.WriteFile(caConfig, []byte(rootCAConfig), 0600); err != nil {
		return fmt.Errorf("write root CA config: %w", err)
	}
	rsaReq := []string{"req", "-new", "-x509", "-sha256", "-config", caConfig, "-extensions", "v3_ca", "-key", rsaKey, "-subj", caSubject(organization, "RSA"), "-days", "3650", "-out", rsaCert}
	sm2Req := []string{"req", "-new", "-x509", "-sm3", "-config", caConfig, "-extensions", "v3_ca", "-key", sm2Key, "-subj", caSubject(organization, "SM2"), "-days", "3650", "-out", sm2Cert}
	commands := [][]string{
		{"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", rsaKey},
		rsaReq,
		{"verify", "-CAfile", rsaCert, rsaCert},
		{"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:SM2", "-out", sm2Key},
		sm2Req,
		{"verify", "-CAfile", sm2Cert, sm2Cert},
	}
	if err := e.runAll(ctx, commands); err != nil {
		return err
	}
	if err := secureGeneratedFiles(rsaKey, rsaCert, sm2Key, sm2Cert, caConfig); err != nil {
		return err
	}
	if err := os.Rename(temp, final); err != nil {
		return fmt.Errorf("publish certificate authorities: %w", err)
	}
	return syncDirectory(pkiDir)
}

func (e *Engine) PublishCRL(ctx context.Context, kind string, validCerts, revokedCerts []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if kind != "rsa" && kind != "sm2" {
		return errors.New("CRL kind must be rsa or sm2")
	}
	pkiDir := filepath.Join(e.store.root, "pki")
	caDir := filepath.Join(pkiDir, "ca", kind)
	temp, err := os.MkdirTemp(pkiDir, ".crl-"+kind+"-*")
	if err != nil {
		return fmt.Errorf("create temporary CRL directory: %w", err)
	}
	defer os.RemoveAll(temp)
	if err := os.Chmod(temp, 0700); err != nil {
		return fmt.Errorf("secure temporary CRL directory: %w", err)
	}
	if err := os.Mkdir(filepath.Join(temp, "newcerts"), 0700); err != nil {
		return fmt.Errorf("create temporary certificate database: %w", err)
	}
	index := filepath.Join(temp, "index.txt")
	attr := filepath.Join(temp, "index.txt.attr")
	crlNumber := filepath.Join(temp, "crlnumber")
	config := filepath.Join(temp, "ca.cnf")
	if err := os.WriteFile(index, nil, 0600); err != nil {
		return fmt.Errorf("initialize temporary CA index: %w", err)
	}
	if err := os.WriteFile(attr, []byte("unique_subject = no\n"), 0600); err != nil {
		return fmt.Errorf("initialize temporary CA attributes: %w", err)
	}
	number, err := os.ReadFile(filepath.Join(caDir, "crlnumber"))
	if errors.Is(err, os.ErrNotExist) {
		number = []byte("1000\n")
	} else if err != nil {
		return fmt.Errorf("read CRL number: %w", err)
	}
	if err := os.WriteFile(crlNumber, number, 0600); err != nil {
		return fmt.Errorf("initialize CRL number: %w", err)
	}
	if err := os.WriteFile(config, []byte(caDatabaseConfig(temp, caDir)), 0600); err != nil {
		return fmt.Errorf("write CRL configuration: %w", err)
	}
	all := append(append([]string(nil), validCerts...), revokedCerts...)
	for _, cert := range all {
		if _, err := e.runner.Run(ctx, "ca", "-batch", "-config", config, "-valid", cert); err != nil {
			return fmt.Errorf("register certificate for CRL: %w", err)
		}
	}
	for _, cert := range revokedCerts {
		if _, err := e.runner.Run(ctx, "ca", "-batch", "-config", config, "-revoke", cert, "-crl_reason", "unspecified"); err != nil {
			return fmt.Errorf("revoke certificate: %w", err)
		}
	}
	generated := filepath.Join(temp, kind+".crl.pem")
	if _, err := e.runner.Run(ctx, "ca", "-batch", "-config", config, "-gencrl", "-out", generated); err != nil {
		return fmt.Errorf("generate CRL: %w", err)
	}
	if _, err := e.runner.Run(ctx, "crl", "-in", generated, "-noout", "-verify", "-CAfile", filepath.Join(caDir, "root-ca.crt")); err != nil {
		return fmt.Errorf("verify CRL: %w", err)
	}
	if err := os.Chmod(generated, 0644); err != nil {
		return fmt.Errorf("set CRL permissions: %w", err)
	}
	crlDir := filepath.Join(pkiDir, "crl")
	if err := os.MkdirAll(crlDir, 0700); err != nil {
		return fmt.Errorf("create CRL directory: %w", err)
	}
	if err := replaceFile(generated, filepath.Join(crlDir, kind+".crl.pem")); err != nil {
		return err
	}
	for _, pair := range [][2]string{{index, filepath.Join(caDir, "index.txt")}, {attr, filepath.Join(caDir, "index.txt.attr")}, {crlNumber, filepath.Join(caDir, "crlnumber")}} {
		if err := replaceFile(pair[0], pair[1]); err != nil {
			return err
		}
		if err := os.Chmod(pair[1], 0600); err != nil {
			return fmt.Errorf("secure CA database file: %w", err)
		}
	}
	return syncDirectory(crlDir)
}

func (e *Engine) IssueRSA(ctx context.Context, req Request) (Bundle, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ValidateRequest(req); err != nil {
		return Bundle{}, err
	}
	temp, final, err := e.beginBundle(req.Name)
	if err != nil {
		return Bundle{}, err
	}
	defer os.RemoveAll(temp)
	serial, err := e.store.NextSerial()
	if err != nil {
		return Bundle{}, err
	}
	ext, err := BuildExtensionConfig(req, KindRSA)
	if err != nil {
		return Bundle{}, err
	}
	extPath := filepath.Join(temp, "rsa-ext.cnf")
	if err := os.WriteFile(extPath, []byte(ext), 0600); err != nil {
		return Bundle{}, fmt.Errorf("write RSA extensions: %w", err)
	}
	key := filepath.Join(temp, "server-rsa.key")
	csr := filepath.Join(temp, "server-rsa.csr")
	cert := filepath.Join(temp, "server-rsa.crt")
	ca := e.caPaths("rsa")
	commands := [][]string{
		{"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key},
		{"req", "-new", "-sha256", "-config", extPath, "-key", key, "-subj", "/CN=" + req.CommonName, "-out", csr},
		{"x509", "-req", "-sha256", "-in", csr, "-CA", ca.cert, "-CAkey", ca.key, "-set_serial", strconv.FormatUint(serial, 10), "-days", strconv.Itoa(req.ValidDays), "-extfile", extPath, "-extensions", "server_cert", "-out", cert},
		{"verify", "-CAfile", ca.cert, cert},
	}
	if err := e.runAll(ctx, commands); err != nil {
		return Bundle{}, err
	}
	if err := secureGeneratedFiles(key, csr, cert, extPath); err != nil {
		return Bundle{}, err
	}
	if err := publishBundle(temp, final); err != nil {
		return Bundle{}, err
	}
	return Bundle{CertificatePath: filepath.Join(final, filepath.Base(cert)), KeyPath: filepath.Join(final, filepath.Base(key)), Serial: serial}, nil
}

func (e *Engine) IssueTLCP(ctx context.Context, req Request) (TLCPBundle, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ValidateRequest(req); err != nil {
		return TLCPBundle{}, err
	}
	temp, final, err := e.beginBundle(req.Name)
	if err != nil {
		return TLCPBundle{}, err
	}
	defer os.RemoveAll(temp)
	signSerial, err := e.store.NextSerial()
	if err != nil {
		return TLCPBundle{}, err
	}
	encSerial, err := e.store.NextSerial()
	if err != nil {
		return TLCPBundle{}, err
	}
	signExt, err := BuildExtensionConfig(req, KindTLCPSign)
	if err != nil {
		return TLCPBundle{}, err
	}
	encExt, err := BuildExtensionConfig(req, KindTLCPEnc)
	if err != nil {
		return TLCPBundle{}, err
	}
	signExtPath := filepath.Join(temp, "sign-ext.cnf")
	encExtPath := filepath.Join(temp, "enc-ext.cnf")
	if err := os.WriteFile(signExtPath, []byte(signExt), 0600); err != nil {
		return TLCPBundle{}, fmt.Errorf("write signing extensions: %w", err)
	}
	if err := os.WriteFile(encExtPath, []byte(encExt), 0600); err != nil {
		return TLCPBundle{}, fmt.Errorf("write encryption extensions: %w", err)
	}
	signKey, signCSR, signCert := bundleFiles(temp, "server-sign")
	encKey, encCSR, encCert := bundleFiles(temp, "server-enc")
	ca := e.caPaths("sm2")
	commands := append(sm2CertificateCommands(req, signKey, signCSR, signCert, signExtPath, signSerial, ca),
		sm2CertificateCommands(req, encKey, encCSR, encCert, encExtPath, encSerial, ca)...)
	commands = append(commands,
		[]string{"verify", "-CAfile", ca.cert, signCert},
		[]string{"verify", "-CAfile", ca.cert, encCert},
	)
	if err := e.runAll(ctx, commands); err != nil {
		return TLCPBundle{}, err
	}
	if err := secureGeneratedFiles(signKey, signCSR, signCert, encKey, encCSR, encCert, signExtPath, encExtPath); err != nil {
		return TLCPBundle{}, err
	}
	if err := publishBundle(temp, final); err != nil {
		return TLCPBundle{}, err
	}
	return TLCPBundle{
		Signing:    Bundle{CertificatePath: filepath.Join(final, filepath.Base(signCert)), KeyPath: filepath.Join(final, filepath.Base(signKey)), Serial: signSerial},
		Encryption: Bundle{CertificatePath: filepath.Join(final, filepath.Base(encCert)), KeyPath: filepath.Join(final, filepath.Base(encKey)), Serial: encSerial},
	}, nil
}

type caFiles struct{ cert, key string }

func (e *Engine) caPaths(kind string) caFiles {
	dir := filepath.Join(e.store.root, "pki", "ca", kind)
	return caFiles{cert: filepath.Join(dir, "root-ca.crt"), key: filepath.Join(dir, "root-ca.key")}
}

func (e *Engine) beginBundle(name string) (string, string, error) {
	issued := filepath.Join(e.store.root, "pki", "issued")
	if err := os.MkdirAll(issued, 0700); err != nil {
		return "", "", fmt.Errorf("create issued directory: %w", err)
	}
	final := filepath.Join(issued, name)
	if _, err := os.Lstat(final); err == nil {
		return "", "", fmt.Errorf("certificate bundle %q already exists", name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("inspect certificate bundle: %w", err)
	}
	temp, err := os.MkdirTemp(issued, "."+name+"-*")
	if err != nil {
		return "", "", fmt.Errorf("create temporary bundle: %w", err)
	}
	if err := os.Chmod(temp, 0700); err != nil {
		os.RemoveAll(temp)
		return "", "", fmt.Errorf("secure temporary bundle: %w", err)
	}
	return temp, final, nil
}

func (e *Engine) runAll(ctx context.Context, commands [][]string) error {
	for _, args := range commands {
		if _, err := e.runner.Run(ctx, args...); err != nil {
			return fmt.Errorf("certificate operation failed: %w", err)
		}
	}
	return nil
}

func bundleFiles(dir, prefix string) (string, string, string) {
	return filepath.Join(dir, prefix+".key"), filepath.Join(dir, prefix+".csr"), filepath.Join(dir, prefix+".crt")
}

func sm2CertificateCommands(req Request, key, csr, cert, extPath string, serial uint64, ca caFiles) [][]string {
	return [][]string{
		{"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:SM2", "-out", key},
		{"req", "-new", "-sm3", "-config", extPath, "-key", key, "-subj", "/CN=" + req.CommonName, "-out", csr},
		{"x509", "-req", "-sm3", "-in", csr, "-CA", ca.cert, "-CAkey", ca.key, "-set_serial", strconv.FormatUint(serial, 10), "-days", strconv.Itoa(req.ValidDays), "-extfile", extPath, "-extensions", "server_cert", "-out", cert},
	}
}

func secureGeneratedFiles(paths ...string) error {
	for _, path := range paths {
		mode := os.FileMode(0644)
		if filepath.Ext(path) == ".key" || filepath.Ext(path) == ".csr" || filepath.Ext(path) == ".cnf" {
			mode = 0600
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("secure generated file %q: %w", filepath.Base(path), err)
		}
	}
	return nil
}

func publishBundle(temp, final string) error {
	if err := os.Rename(temp, final); err != nil {
		return fmt.Errorf("publish certificate bundle: %w", err)
	}
	return syncDirectory(filepath.Dir(final))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func caSubject(organization, algorithm string) string {
	return "/C=CN/O=" + organization + "/CN=" + organization + " " + algorithm + " Root CA"
}

func caDatabaseConfig(databaseDir, caDir string) string {
	return fmt.Sprintf(`[ca]
default_ca=certarium_ca

[certarium_ca]
database=%s/index.txt
unique_subject=no
new_certs_dir=%s/newcerts
certificate=%s/root-ca.crt
private_key=%s/root-ca.key
crlnumber=%s/crlnumber
default_md=default
default_crl_days=7
policy=policy_any

[policy_any]
commonName=supplied
countryName=optional
stateOrProvinceName=optional
localityName=optional
organizationName=optional
organizationalUnitName=optional
emailAddress=optional
`, databaseDir, databaseDir, caDir, caDir, databaseDir)
}

func replaceFile(source, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return fmt.Errorf("publish %q: %w", filepath.Base(destination), err)
	}
	return nil
}

const rootCAConfig = `[req]
distinguished_name=req_dn
prompt=no

[req_dn]

[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
`
