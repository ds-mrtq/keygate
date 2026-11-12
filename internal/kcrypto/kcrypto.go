// Package kcrypto holds the KeyGate cryptographic primitives (DESIGN.md sec 2).
package kcrypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Domain separation labels. Every signed/MACed/HKDF string starts with one.
const (
	LabelRecord     = "kg/v1/record\x00"
	LabelMember     = "kg/v1/member\x00"
	LabelCheckpoint = "kg/v1/checkpoint\x00"
	LabelRelayReq   = "kg/v1/relay-req\x00"
	LabelApproval   = "kg/v1/approval\x00"
	LabelItemKey    = "kg/v1/item-key\x00"
	LabelWrap       = "kg/v1/wrap\x00"
	LabelRecovery   = "kg/v1/recovery\x00"
	LabelLocalMac   = "kg/v1/local-mac\x00"

	LabelMsg         = "kg/v1/msg\x00"
	LabelMsgKey      = "kg/v1/msg-key\x00"
	LabelApprovalReq = "kg/v1/approval-req\x00"
)

// Sizes.
const (
	KeySize   = 32
	NonceSize = chacha20poly1305.NonceSizeX
)

// Errors.
var (
	ErrBadSignature = errors.New("keygate: bad signature")
	ErrDecrypt      = errors.New("keygate: decryption failed")
	ErrBadWrap      = errors.New("keygate: malformed key wrap")
)

// Enc builds length-prefixed canonical byte strings.
type Enc struct{ b []byte }

// NewEnc starts a canonical string with the given domain label.
func NewEnc(label string) *Enc { return &Enc{b: []byte(label)} }

// U64 appends a big-endian uint64.
func (e *Enc) U64(n uint64) *Enc { e.b = binary.BigEndian.AppendUint64(e.b, n); return e }

// LP appends lp(p): uint32 big-endian length then bytes.
func (e *Enc) LP(p []byte) *Enc {
	e.b = binary.BigEndian.AppendUint32(e.b, uint32(len(p)))
	e.b = append(e.b, p...)
	return e
}

// LPS appends lp(s).
func (e *Enc) LPS(s string) *Enc { return e.LP([]byte(s)) }

// LPOpt appends lp(s) or lp("") for nil.
func (e *Enc) LPOpt(s *string) *Enc {
	if s == nil {
		return e.LP(nil)
	}
	return e.LPS(*s)
}

// Bytes returns the accumulated bytes.
func (e *Enc) Bytes() []byte { return e.b }

// B64 encodes standard base64 with padding.
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// UnB64 decodes strict standard base64 (rejects non-canonical encodings).
func UnB64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") { // the stdlib decoder silently skips CR/LF
		return nil, base64.CorruptInputError(0)
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}

// SHA256Ref returns "sha256:" + hex(sha256(parts...)).
func SHA256Ref(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// IsHashRef reports whether s is "sha256:" + 64 lowercase hex chars.
func IsHashRef(s string) bool {
	const p = "sha256:"
	if len(s) != len(p)+64 || !strings.HasPrefix(s, p) {
		return false
	}
	for _, c := range s[len(p):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

var idEnc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewID returns prefix + n random lowercase base32 characters.
func NewID(prefix string, n int) string {
	raw := make([]byte, (n*5+7)/8)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		panic(err)
	}
	return prefix + idEnc.EncodeToString(raw)[:n]
}

// ValidID reports whether s is prefix + exactly n chars of [a-z2-7].
func ValidID(prefix string, n int, s string) bool {
	if len(s) != len(prefix)+n || !strings.HasPrefix(s, prefix) {
		return false
	}
	for _, c := range s[len(prefix):] {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// ID formats used across the vault.
const (
	VaultPrefix, VaultIDLen   = "vlt_", 16
	DevicePrefix, DeviceIDLen = "dev_", 10
	ItemPrefix, ItemIDLen     = "itm_", 16
)

// ValidVaultID, ValidDeviceID and ValidItemID check ID syntax.
func ValidVaultID(s string) bool  { return ValidID(VaultPrefix, VaultIDLen, s) }
func ValidDeviceID(s string) bool { return ValidID(DevicePrefix, DeviceIDLen, s) }
func ValidItemID(s string) bool   { return ValidID(ItemPrefix, ItemIDLen, s) }

// NewVaultID, NewDeviceID and NewItemID generate random IDs.
func NewVaultID() string  { return NewID(VaultPrefix, VaultIDLen) }
func NewDeviceID() string { return NewID(DevicePrefix, DeviceIDLen) }
func NewItemID() string   { return NewID(ItemPrefix, ItemIDLen) }

// RandBytes returns n random bytes.
func RandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

// NewVaultKey returns a fresh 32 byte vault key.
func NewVaultKey() []byte { return RandBytes(KeySize) }

// HKDF derives n bytes with HKDF-SHA256 (no salt).
func HKDF(ikm, info []byte, n int) []byte {
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, nil, info), out); err != nil {
		panic(err)
	}
	return out
}

// Argon2Params are Argon2id cost parameters (stored in the genesis event).
type Argon2Params struct {
	T uint32 `json:"t"`
	M uint32 `json:"m"` // KiB
	P uint8  `json:"p"`
}

// DefaultArgon2 is t=3, m=64 MiB, p=4 (DESIGN sec 2).
var DefaultArgon2 = Argon2Params{T: 3, M: 64 * 1024, P: 4}

// Validate bounds the parameters so hostile genesis events cannot exhaust memory.
func (p Argon2Params) Validate() error {
	if p.T < 1 || p.T > 32 || p.P < 1 || p.P > 32 || p.M < 8*uint32(p.P) || p.M > 1<<20 {
		return errors.New("keygate: invalid argon2 params")
	}
	return nil
}

// Argon2ID derives a 32 byte key from a password.
func Argon2ID(pwd, salt []byte, p Argon2Params) []byte {
	return argon2.IDKey(pwd, salt, p.T, p.M, p.P, 32)
}

// MAC returns HMAC-SHA256(key, data).
func MAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// GenerateSignKey creates an Ed25519 key pair.
func GenerateSignKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// X25519Public derives the public key for a private scalar.
func X25519Public(priv [32]byte) [32]byte {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	var out [32]byte
	copy(out[:], pub)
	return out
}

// GenerateX25519 creates an X25519 key pair.
func GenerateX25519() (priv, pub [32]byte) {
	copy(priv[:], RandBytes(32))
	return priv, X25519Public(priv)
}

// Seal encrypts with XChaCha20-Poly1305.
func Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("keygate: bad nonce size")
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts with XChaCha20-Poly1305; any failure is ErrDecrypt.
func Open(key, nonce, ct, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize || len(key) != KeySize {
		return nil, ErrDecrypt
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt, err := a.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// ItemKey = HKDF(vaultKey, "kg/v1/item-key\0"+lp(vault)+u64(epoch)+lp(item)).
func ItemKey(vaultKey []byte, vault string, epoch uint64, item string) []byte {
	info := NewEnc(LabelItemKey).LPS(vault).U64(epoch).LPS(item).Bytes()
	return HKDF(vaultKey, info, KeySize)
}

// Wrap is a vault key wrapped for one recipient. All fields are base64 std except Rcpt.
type Wrap struct {
	Rcpt  string `json:"rcpt"`
	Eph   string `json:"eph"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// Validate checks the field encodings and sizes.
func (w Wrap) Validate() error {
	eph, err1 := UnB64(w.Eph)
	n, err2 := UnB64(w.Nonce)
	ct, err3 := UnB64(w.CT)
	if err1 != nil || err2 != nil || err3 != nil || len(eph) != 32 || len(n) != NonceSize || len(ct) != KeySize+chacha20poly1305.Overhead || w.Rcpt == "" {
		return ErrBadWrap
	}
	return nil
}

func wrapInfo(vault string, epoch uint64, ephPub, rcptPub [32]byte) []byte {
	return NewEnc(LabelWrap).LPS(vault).U64(epoch).LP(ephPub[:]).LP(rcptPub[:]).Bytes()
}

// WrapKeyWith wraps vaultKey for rcptPub using the supplied ephemeral key and nonce (deterministic; for vectors).
func WrapKeyWith(ephPriv [32]byte, nonce [24]byte, vault string, epoch uint64, rcptID string, rcptPub [32]byte, vaultKey []byte) (Wrap, error) {
	ephPub := X25519Public(ephPriv)
	shared, err := curve25519.X25519(ephPriv[:], rcptPub[:])
	if err != nil {
		return Wrap{}, err
	}
	info := wrapInfo(vault, epoch, ephPub, rcptPub)
	k := HKDF(shared, info, KeySize)
	ct, err := Seal(k, nonce[:], vaultKey, info)
	if err != nil {
		return Wrap{}, err
	}
	return Wrap{Rcpt: rcptID, Eph: B64(ephPub[:]), Nonce: B64(nonce[:]), CT: B64(ct)}, nil
}

// WrapKey wraps vaultKey for a recipient with a fresh ephemeral key and random nonce.
func WrapKey(vault string, epoch uint64, rcptID string, rcptPub [32]byte, vaultKey []byte) (Wrap, error) {
	eph, _ := GenerateX25519()
	var n [24]byte
	copy(n[:], RandBytes(24))
	return WrapKeyWith(eph, n, vault, epoch, rcptID, rcptPub, vaultKey)
}

// UnwrapKey recovers the vault key using the recipient private key.
func UnwrapKey(vault string, epoch uint64, w Wrap, rcptPriv [32]byte) ([]byte, error) {
	if err := w.Validate(); err != nil {
		return nil, err
	}
	ephRaw, _ := UnB64(w.Eph)
	nonce, _ := UnB64(w.Nonce)
	ct, _ := UnB64(w.CT)
	var ephPub [32]byte
	copy(ephPub[:], ephRaw)
	shared, err := curve25519.X25519(rcptPriv[:], ephPub[:])
	if err != nil {
		return nil, ErrDecrypt
	}
	info := wrapInfo(vault, epoch, ephPub, X25519Public(rcptPriv))
	k := HKDF(shared, info, KeySize)
	key, err := Open(k, nonce, ct, info)
	if err != nil {
		return nil, fmt.Errorf("%w (unwrap)", ErrDecrypt)
	}
	return key, nil
}
