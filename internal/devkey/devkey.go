// Package devkey stores the device private key material (DESIGN.md sec 3).
//
// The secret is an opaque blob (the store packs Ed25519 seed || X25519 private key).
// Backends: Windows DPAPI, macOS Keychain via /usr/bin/security, Linux Argon2id-encrypted
// file (also the fallback elsewhere), and a plain file for tests only
// (KG_DEVKEY_BACKEND=plain, honoured only in `-tags kgtest` builds).
package devkey

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"keygate/internal/fsx"
	"keygate/internal/kcrypto"
)

// ErrNotFound is returned by Load when no key is stored for the device.
var ErrNotFound = errors.New("keygate: device key not found")

// EnvBackend selects the backend explicitly; only "plain" is recognised.
const EnvBackend = "KG_DEVKEY_BACKEND"

// Store saves and loads the private key blob of one device.
type Store interface {
	Name() string
	Save(dev string, secret []byte) error
	Load(dev string) ([]byte, error)
}

// PasswordFunc asks the user for the device unlock password (confirm=true when creating).
type PasswordFunc func(confirm bool) (string, error)

// Options configure Open.
type Options struct {
	Password PasswordFunc          // required for the encrypted-file backend
	Argon    *kcrypto.Argon2Params // optional override (tests); default kcrypto.DefaultArgon2
}

// Open picks the backend for runtime.GOOS rooted at home (the KG_HOME directory).
func Open(home string, opt Options) (Store, error) {
	if os.Getenv(EnvBackend) == "plain" {
		if !PlainAllowed {
			return nil, errors.New("keygate: KG_DEVKEY_BACKEND=plain is only honoured by binaries built with -tags kgtest")
		}
		fmt.Fprintln(os.Stderr, "keygate: WARNING: KG_DEVKEY_BACKEND=plain stores the device key unencrypted; test use only")
		return NewPlain(home), nil
	}
	return openNative(home, opt)
}

// ---- plain (tests) ----

type plain struct{ path string }

// NewPlain returns the unencrypted test backend.
func NewPlain(home string) Store { return &plain{path: filepath.Join(home, "device.key.plain")} }

func (p *plain) Name() string { return "plain" }

func (p *plain) Save(dev string, secret []byte) error {
	return fsx.WriteAtomic(p.path, []byte(kcrypto.B64(secret)))
}

func (p *plain) Load(dev string) ([]byte, error) {
	b, err := os.ReadFile(p.path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return kcrypto.UnB64(string(b))
}

// ---- encrypted file (Linux and fallback) ----

const fileMagic = "KGDK1"

type encFile struct {
	path string
	opt  Options
}

// NewFile returns the Argon2id-encrypted file backend (device.key.enc, mode 0600).
func NewFile(home string, opt Options) Store {
	return &encFile{path: filepath.Join(home, "device.key.enc"), opt: opt}
}

func (f *encFile) Name() string { return "file" }

func (f *encFile) params() kcrypto.Argon2Params {
	if f.opt.Argon != nil {
		return *f.opt.Argon
	}
	return kcrypto.DefaultArgon2
}

func (f *encFile) Save(dev string, secret []byte) error {
	if f.opt.Password == nil {
		return errors.New("keygate: device unlock password required")
	}
	pw, err := f.opt.Password(true)
	if err != nil {
		return err
	}
	salt, nonce := kcrypto.RandBytes(16), kcrypto.RandBytes(kcrypto.NonceSize)
	key := kcrypto.Argon2ID([]byte(pw), salt, f.params())
	ct, err := kcrypto.Seal(key, nonce, secret, []byte(dev))
	if err != nil {
		return err
	}
	out := append([]byte(fileMagic), salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return fsx.WriteAtomic(f.path, out)
}

func (f *encFile) Load(dev string) ([]byte, error) {
	b, err := os.ReadFile(f.path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	hdr := len(fileMagic) + 16 + kcrypto.NonceSize
	if len(b) <= hdr || string(b[:len(fileMagic)]) != fileMagic {
		return nil, errors.New("keygate: device key file corrupt")
	}
	if f.opt.Password == nil {
		return nil, errors.New("keygate: device unlock password required")
	}
	pw, err := f.opt.Password(false)
	if err != nil {
		return nil, err
	}
	salt := b[len(fileMagic) : len(fileMagic)+16]
	nonce := b[len(fileMagic)+16 : hdr]
	key := kcrypto.Argon2ID([]byte(pw), salt, f.params())
	secret, err := kcrypto.Open(key, nonce, b[hdr:], []byte(dev))
	if err != nil {
		return nil, errors.New("keygate: wrong device password or corrupt key file")
	}
	return secret, nil
}
