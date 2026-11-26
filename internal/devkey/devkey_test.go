package devkey

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"keygate/internal/kcrypto"
)

func TestPlain(t *testing.T) {
	t.Setenv(EnvBackend, "plain")
	if !PlainAllowed {
		if _, err := Open(t.TempDir(), Options{}); err == nil {
			t.Fatal("plain backend must be refused without -tags kgtest")
		}
		t.Skip("needs -tags kgtest")
	}
	home := t.TempDir()
	s, err := Open(home, Options{})
	if err != nil || s.Name() != "plain" {
		t.Fatalf("%v %v", s, err)
	}
	if _, err := s.Load("dev_abcdefghij"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	secret := kcrypto.RandBytes(64)
	if err := s.Save("dev_abcdefghij", secret); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load("dev_abcdefghij")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("load: %v", err)
	}
}

func TestEncryptedFile(t *testing.T) {
	home := t.TempDir()
	low := kcrypto.Argon2Params{T: 1, M: 64, P: 1}
	pw := "unlock-password"
	s := NewFile(home, Options{Password: func(bool) (string, error) { return pw, nil }, Argon: &low})
	secret := kcrypto.RandBytes(64)
	if err := s.Save("dev_abcdefghij", secret); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(home, "device.key.enc")); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode())
		}
	}
	raw, _ := os.ReadFile(filepath.Join(home, "device.key.enc"))
	if bytes.Contains(raw, secret) {
		t.Fatal("secret stored in clear")
	}
	got, err := s.Load("dev_abcdefghij")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("load: %v", err)
	}
	if _, err := s.Load("dev_zzzzzzzzzz"); err == nil {
		t.Fatal("device id is bound as AAD")
	}
	pw = "wrong"
	if _, err := s.Load("dev_abcdefghij"); err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestNativeFallbackEncryptedFile(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("encrypted-file fallback only")
	}
	t.Setenv(EnvBackend, "")
	home := t.TempDir()
	const dev = "dev_abcdefghij"
	secret := []byte("fake native device key")
	var prompts []bool
	password := func(confirm bool) (string, error) {
		prompts = append(prompts, confirm)
		return "fake device password", nil
	}
	s, err := Open(home, Options{Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "file" {
		t.Fatalf("native fallback = %q, want encrypted file", s.Name())
	}
	if got, err := s.Load(dev); got != nil || !errors.Is(err, ErrNotFound) || len(prompts) != 0 {
		t.Fatalf("missing key: want ErrNotFound without asking for a password, got %v, prompts %v", err, prompts)
	}
	if err := s.Save(dev, secret); err != nil {
		t.Fatal(err)
	}
	reader := NewFile(home, Options{Password: password, Argon: &kcrypto.DefaultArgon2})
	if got, err := reader.Load(dev); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("read without an Argon2 override on save: %v", err)
	}
	if len(prompts) != 2 || !prompts[0] || prompts[1] {
		t.Fatalf("save must confirm the password, load must not; prompts %v", prompts)
	}
}

func TestEncryptedFilePasswordFailures(t *testing.T) {
	home := t.TempDir()
	const dev = "dev_abcdefghij"
	low := kcrypto.Argon2Params{T: 1, M: 64, P: 1}
	secret := []byte("fake existing device key")
	s := NewFile(home, Options{Argon: &low, Password: func(bool) (string, error) { return "fake device password", nil }})
	if err := s.Save(dev, secret); err != nil {
		t.Fatal(err)
	}
	canceled := errors.New("fake password prompt canceled")
	for _, tc := range []struct {
		name     string
		password PasswordFunc
		wantErr  error
	}{
		{name: "no password callback"},
		{name: "canceled password prompt", password: func(bool) (string, error) { return "", canceled }, wantErr: canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fail := NewFile(home, Options{Argon: &low, Password: tc.password})
			if err := fail.Save(dev, []byte("fake replacement key")); err == nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("save did not propagate password failure: %v", err)
			}
			if got, err := fail.Load(dev); got != nil || err == nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("load did not fail without returning key data: %v", err)
			}
			if got, err := s.Load(dev); err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("failed save must leave the original key readable: %v", err)
			}
		})
	}
}

func TestEncryptedFileRejectsCorruption(t *testing.T) {
	home := t.TempDir()
	const dev = "dev_abcdefghij"
	low := kcrypto.Argon2Params{T: 1, M: 64, P: 1}
	prompts := 0
	s := NewFile(home, Options{Argon: &low, Password: func(bool) (string, error) {
		prompts++
		return "fake device password", nil
	}})
	if err := s.Save(dev, []byte("fake encrypted device key")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "device.key.enc")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	badMagic := bytes.Clone(raw)
	badMagic[0] ^= 1
	badCiphertext := bytes.Clone(raw)
	badCiphertext[len(badCiphertext)-1] ^= 1
	for _, tc := range []struct {
		name        string
		file        []byte
		wantPrompts int
	}{
		{name: "truncated header", file: raw[:1]},
		{name: "wrong file format", file: badMagic},
		{name: "modified ciphertext", file: badCiphertext, wantPrompts: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.file, 0o600); err != nil {
				t.Fatal(err)
			}
			prompts = 0
			if got, err := s.Load(dev); got != nil || err == nil || errors.Is(err, ErrNotFound) {
				t.Fatalf("corrupt key must be rejected without returning key data: %v", err)
			}
			if prompts != tc.wantPrompts {
				t.Fatalf("password prompts: got %d, want %d", prompts, tc.wantPrompts)
			}
		})
	}
}

func TestNativeWindowsDPAPI(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI only")
	}
	t.Setenv(EnvBackend, "")
	home := t.TempDir()
	s, err := Open(home, Options{})
	if err != nil || s.Name() != "dpapi" {
		t.Fatalf("%v %v", s, err)
	}
	if got, err := s.Load("dev_abcdefghij"); got != nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound for an absent DPAPI file, got %v", err)
	}
	secret := kcrypto.RandBytes(64)
	if err := s.Save("dev_abcdefghij", secret); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "device.key.dpapi")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("secret stored in clear")
	}
	got, err := s.Load("dev_abcdefghij")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("load: %v", err)
	}
	if _, err := s.Load("dev_zzzzzzzzzz"); err == nil {
		t.Fatal("entropy (device id) must bind the blob")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Load("dev_abcdefghij"); got != nil || err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("empty DPAPI file must be rejected as corrupt, got %v", err)
	}
}
