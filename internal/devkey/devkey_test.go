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

// The native backend (DPAPI on Windows, keychain on macOS, file elsewhere) is exercised on Windows only.
func TestNativeWindowsDPAPI(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI only")
	}
	home := t.TempDir()
	s, err := Open(home, Options{})
	if err != nil || s.Name() != "dpapi" {
		t.Fatalf("%v %v", s, err)
	}
	secret := kcrypto.RandBytes(64)
	if err := s.Save("dev_abcdefghij", secret); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(home, "device.key.dpapi"))
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
}
