package backup

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	magic         = "CERTARIUM-BACKUP-V1\n"
	maxBackupSize = 256 << 20
	kdfIterations = 200_000
)

type manifest struct {
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	Files     map[string]string `json:"files"`
}

type entry struct {
	name string
	mode os.FileMode
	data []byte
}

func Create(dataDir, configDir, output, password string) error {
	if password == "" {
		return errors.New("backup password is required")
	}
	entries, err := collect(dataDir, configDir)
	if err != nil {
		return err
	}
	plain, err := makeArchive(entries)
	if err != nil {
		return err
	}
	encrypted, err := encrypt(plain, password)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return fmt.Errorf("create backup output directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(output), ".certarium-backup-*.tmp")
	if err != nil {
		return fmt.Errorf("create backup output: %w", err)
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(encrypted); err != nil {
		temp.Close()
		return fmt.Errorf("write backup: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync backup: %w", err)
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, output); err != nil {
		return fmt.Errorf("publish backup: %w", err)
	}
	return nil
}

func Restore(input, dataDir, configDir, password string, replace bool) error {
	if password == "" {
		return errors.New("backup password is required")
	}
	info, err := os.Lstat(input)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBackupSize {
		return errors.New("backup input must be a bounded regular file")
	}
	encrypted, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	plain, err := decrypt(encrypted, password)
	if err != nil {
		return err
	}
	entries, err := readArchive(plain)
	if err != nil {
		return err
	}
	if !replace {
		for _, destination := range []string{dataDir, configDir} {
			if _, err := os.Lstat(destination); err == nil || !errors.Is(err, os.ErrNotExist) {
				return errors.New("restore destination already exists")
			}
		}
	}
	dataTemp, err := materialize(filepath.Dir(dataDir), "data", entries)
	if err != nil {
		return err
	}
	defer os.RemoveAll(dataTemp)
	configTemp, err := materialize(filepath.Dir(configDir), "config", entries)
	if err != nil {
		return err
	}
	defer os.RemoveAll(configTemp)
	return publish([]publication{{temp: dataTemp, destination: dataDir}, {temp: configTemp, destination: configDir}}, replace)
}

func collect(dataDir, configDir string) ([]entry, error) {
	var entries []entry
	for _, source := range []struct{ prefix, root string }{{"data", dataDir}, {"config", configDir}} {
		err := filepath.WalkDir(source.root, func(file string, item os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if file == source.root {
				return nil
			}
			info, err := os.Lstat(file)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("backup source contains unsupported file %q", file)
			}
			relative, err := filepath.Rel(source.root, file)
			if err != nil {
				return err
			}
			name := path.Join(source.prefix, filepath.ToSlash(relative))
			if !safeArchivePath(name) {
				return fmt.Errorf("unsafe backup path %q", name)
			}
			data, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			entries = append(entries, entry{name: name, mode: info.Mode().Perm(), data: data})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("collect %s backup files: %w", source.prefix, err)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries, nil
}

func makeArchive(entries []entry) ([]byte, error) {
	value := manifest{Version: 1, CreatedAt: time.Now().UTC(), Files: make(map[string]string, len(entries))}
	for _, file := range entries {
		sum := sha256.Sum256(file.data)
		value.Files[file.name] = hex.EncodeToString(sum[:])
	}
	manifestData, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	all := append(append([]entry(nil), entries...), entry{name: "manifest.json", mode: 0600, data: manifestData})
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, file := range all {
		header := &tar.Header{Name: file.name, Mode: int64(file.mode.Perm()), Size: int64(len(file.data)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}
		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := writer.Write(file.data); err != nil {
			return nil, err
		}
		if buffer.Len() > maxBackupSize {
			return nil, errors.New("backup exceeds size limit")
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func readArchive(plain []byte) ([]entry, error) {
	reader := tar.NewReader(bytes.NewReader(plain))
	files := make(map[string]entry)
	var expected manifest
	manifestSeen := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read backup archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || !safeArchivePath(header.Name) || header.Size < 0 || header.Size > maxBackupSize {
			return nil, errors.New("backup contains unsafe archive entry")
		}
		data, err := io.ReadAll(io.LimitReader(reader, maxBackupSize+1))
		if err != nil || len(data) > maxBackupSize {
			return nil, errors.New("backup archive entry exceeds limit")
		}
		if _, duplicate := files[header.Name]; duplicate || (header.Name == "manifest.json" && manifestSeen) {
			return nil, errors.New("backup contains duplicate entry")
		}
		if header.Name == "manifest.json" {
			if err := json.Unmarshal(data, &expected); err != nil || expected.Version != 1 {
				return nil, errors.New("backup manifest is invalid")
			}
			manifestSeen = true
			continue
		}
		files[header.Name] = entry{name: header.Name, mode: os.FileMode(header.Mode) & 0777, data: data}
	}
	if !manifestSeen || len(files) != len(expected.Files) {
		return nil, errors.New("backup manifest does not match archive")
	}
	entries := make([]entry, 0, len(files))
	for name, file := range files {
		sum := sha256.Sum256(file.data)
		if expected.Files[name] != hex.EncodeToString(sum[:]) {
			return nil, errors.New("backup file hash mismatch")
		}
		entries = append(entries, file)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries, nil
}

func safeArchivePath(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name {
		return false
	}
	if name == "manifest.json" {
		return true
	}
	return strings.HasPrefix(name, "data/") || strings.HasPrefix(name, "config/")
}

func encrypt(plain []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := pbkdf2([]byte(password), salt, kdfIterations, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	result := append([]byte(magic), salt...)
	result = append(result, nonce...)
	return gcm.Seal(result, nonce, plain, []byte(magic)), nil
}

func decrypt(data []byte, password string) ([]byte, error) {
	minimum := len(magic) + 16 + 12 + 16
	if len(data) < minimum || string(data[:len(magic)]) != magic {
		return nil, errors.New("backup format is invalid")
	}
	salt := data[len(magic) : len(magic)+16]
	nonce := data[len(magic)+16 : len(magic)+28]
	ciphertext := data[len(magic)+28:]
	block, err := aes.NewCipher(pbkdf2([]byte(password), salt, kdfIterations, 32))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(magic))
	if err != nil {
		return nil, errors.New("backup password is wrong or artifact is corrupt")
	}
	return plain, nil
}

func pbkdf2(password, salt []byte, iterations, length int) []byte {
	result := make([]byte, 0, length)
	for block := uint32(1); len(result) < length; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], block)
		_, _ = mac.Write(counter[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:length]
}

func materialize(parent, prefix string, entries []entry) (string, error) {
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", err
	}
	temp, err := os.MkdirTemp(parent, ".certarium-restore-*")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(temp, 0700); err != nil {
		os.RemoveAll(temp)
		return "", err
	}
	for _, file := range entries {
		if !strings.HasPrefix(file.name, prefix+"/") {
			continue
		}
		relative := strings.TrimPrefix(file.name, prefix+"/")
		destination := filepath.Join(temp, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			os.RemoveAll(temp)
			return "", err
		}
		if err := os.WriteFile(destination, file.data, file.mode.Perm()); err != nil {
			os.RemoveAll(temp)
			return "", err
		}
	}
	return temp, nil
}

type publication struct{ temp, destination, old string }

func publish(items []publication, replace bool) error {
	for i := range items {
		if err := os.MkdirAll(filepath.Dir(items[i].destination), 0700); err != nil {
			rollback(items, i)
			return err
		}
		if _, err := os.Lstat(items[i].destination); err == nil {
			if !replace {
				rollback(items, i)
				return errors.New("restore destination already exists")
			}
			items[i].old = items[i].destination + fmt.Sprintf(".before-restore-%d", time.Now().UnixNano())
			if err := os.Rename(items[i].destination, items[i].old); err != nil {
				rollback(items, i)
				return err
			}
		}
		if err := os.Rename(items[i].temp, items[i].destination); err != nil {
			rollback(items, i+1)
			return err
		}
		items[i].temp = ""
	}
	for _, item := range items {
		if item.old != "" {
			_ = os.RemoveAll(item.old)
		}
	}
	return nil
}

func rollback(items []publication, count int) {
	for i := count - 1; i >= 0; i-- {
		if items[i].old == "" {
			continue
		}
		_ = os.RemoveAll(items[i].destination)
		_ = os.Rename(items[i].old, items[i].destination)
	}
}
