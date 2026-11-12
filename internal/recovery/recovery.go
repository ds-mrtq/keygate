// Package recovery derives the owner and recovery keys from master password + paper key
// (DESIGN.md sec 3) and encodes the paper key for humans.
package recovery

import (
	"crypto/ed25519"
	"encoding/base32"
	"errors"
	"hash/crc32"
	"strings"

	"keygate/internal/kcrypto"
)

// PaperKeySize is the paper key entropy in bytes.
const PaperKeySize = 32

// ErrPaperKey is returned for malformed paper keys or checksum mismatch.
var ErrPaperKey = errors.New("keygate: invalid paper key (typo or checksum mismatch)")

// Keys are the owner signing key and the recovery X25519 key.
type Keys struct {
	OwnerPriv    ed25519.PrivateKey
	OwnerPub     ed25519.PublicKey
	RecoveryPriv [32]byte
	RecoveryPub  [32]byte
}

// Derive computes the keys: HKDF(Argon2id(pwd,salt) || paperKey, info "kg/v1/recovery\0"+lp(vault)) -> 64 bytes.
func Derive(vault, pwd string, salt []byte, params kcrypto.Argon2Params, paperKey []byte) (*Keys, error) {
	if len(paperKey) != PaperKeySize {
		return nil, ErrPaperKey
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	ikm := append(kcrypto.Argon2ID([]byte(pwd), salt, params), paperKey...)
	info := kcrypto.NewEnc(kcrypto.LabelRecovery).LPS(vault).Bytes()
	okm := kcrypto.HKDF(ikm, info, 64)
	clear(ikm)
	k := &Keys{OwnerPriv: ed25519.NewKeyFromSeed(okm[:32])}
	k.OwnerPub = k.OwnerPriv.Public().(ed25519.PublicKey)
	copy(k.RecoveryPriv[:], okm[32:])
	clear(okm)
	k.RecoveryPub = kcrypto.X25519Public(k.RecoveryPriv)
	return k, nil
}

// Setup is the result of NewSetup.
type Setup struct {
	Keys     *Keys
	Salt     []byte
	Params   kcrypto.Argon2Params
	PaperKey string // human form, shown once
}

// NewSetup generates a salt and paper key and derives the keys for a new vault.
func NewSetup(vault, pwd string, params kcrypto.Argon2Params) (*Setup, error) {
	salt := kcrypto.RandBytes(16)
	paper := kcrypto.RandBytes(PaperKeySize)
	k, err := Derive(vault, pwd, salt, params, paper)
	if err != nil {
		return nil, err
	}
	return &Setup{Keys: k, Salt: salt, Params: params, PaperKey: EncodePaperKey(paper)}, nil
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func checksum(raw []byte) string {
	c := crc32.ChecksumIEEE(raw)
	// 4 base32 chars = 20 bits: the low 20 bits of the CRC.
	var out [4]byte
	for i := 3; i >= 0; i-- {
		out[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[c&31]
		c >>= 5
	}
	return string(out[:])
}

// EncodePaperKey renders the key as base32 groups of 4 chars separated by '-', ending with a 4 char CRC32 group.
func EncodePaperKey(raw []byte) string {
	s := b32.EncodeToString(raw) + checksum(raw)
	var parts []string
	for len(s) > 0 {
		n := 4
		if len(s) < n {
			n = len(s)
		}
		parts = append(parts, s[:n])
		s = s[n:]
	}
	return strings.Join(parts, "-")
}

// ParsePaperKey accepts the printed form (case-insensitive; spaces and dashes ignored) and verifies the checksum.
func ParsePaperKey(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\n", "", "\r", "").Replace(s))
	want := b32.EncodedLen(PaperKeySize) + 4
	if len(s) != want {
		return nil, ErrPaperKey
	}
	raw, err := b32.DecodeString(s[:want-4])
	if err != nil || len(raw) != PaperKeySize || checksum(raw) != s[want-4:] {
		return nil, ErrPaperKey
	}
	return raw, nil
}
