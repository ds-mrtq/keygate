// Package remote holds the phone <-> broker message formats: sealed, signed
// envelopes (ADR-0006 style) and the plaintext protocol carried inside them.
package remote

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"

	"keygate/internal/kcrypto"
	"keygate/internal/store"
)

// ErrBadEnvelope wraps every Open failure.
var ErrBadEnvelope = errors.New("remote: bad envelope")

const timeFmt = "2006-01-02T15:04:05.000Z"

// Envelope is one sealed message line (AES-256-GCM, Ed25519-signed by the sender).
type Envelope struct {
	V     int    `json:"v"`
	From  string `json:"from"`
	To    string `json:"to"`
	ID    string `json:"id"`    // base64 raw-URL of 16 random bytes (22 chars)
	Time  string `json:"time"`  // UTC "2006-01-02T15:04:05.000Z"
	Eph   string `json:"eph"`   // base64 std, 32 bytes
	Nonce string `json:"nonce"` // base64 std, 12 bytes
	CT    string `json:"ct"`    // base64 std
	Sig   string `json:"sig"`   // base64 std, 64 bytes
}

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBadEnvelope, fmt.Sprintf(format, a...))
}

// NewID returns a fresh envelope/message id (22 chars).
func NewID() string { return base64.RawURLEncoding.EncodeToString(kcrypto.RandBytes(16)) }

func msgInfo(vault, from, to, id string, ephPub, toXPub []byte) []byte {
	return kcrypto.NewEnc(kcrypto.LabelMsgKey).LPS(vault).LPS(from).LPS(to).LPS(id).LP(ephPub).LP(toXPub).Bytes()
}

func sigInput(vault, from, to, id, tm string, eph, nonce, ct []byte) []byte {
	return kcrypto.NewEnc(kcrypto.LabelMsg).U64(1).LPS(vault).LPS(from).LPS(to).LPS(id).LPS(tm).LP(eph).LP(nonce).LP(ct).Bytes()
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Seal encrypts plaintext for device `to` with a fresh ephemeral key and signs it as `from`.
func Seal(vault string, from *store.Identity, to string, toXPub [32]byte, plaintext []byte, now time.Time) ([]byte, error) {
	ephPriv, _ := kcrypto.GenerateX25519()
	var nonce [12]byte
	copy(nonce[:], kcrypto.RandBytes(12))
	return SealWith(vault, from, to, toXPub, plaintext, now, ephPriv, nonce, NewID())
}

// SealWith is Seal with caller-supplied ephemeral private key, nonce and id (test vectors).
func SealWith(vault string, from *store.Identity, to string, toXPub [32]byte, plaintext []byte, now time.Time, eph [32]byte, nonce [12]byte, id string) ([]byte, error) {
	ephPub := kcrypto.X25519Public(eph)
	shared, err := curve25519.X25519(eph[:], toXPub[:])
	if err != nil {
		return nil, bad("x25519: %v", err)
	}
	info := msgInfo(vault, from.Dev, to, id, ephPub[:], toXPub[:])
	a, err := gcm(kcrypto.HKDF(shared, info, 32))
	if err != nil {
		return nil, err
	}
	ct := a.Seal(nil, nonce[:], plaintext, info)
	tm := now.UTC().Format(timeFmt)
	sig := ed25519.Sign(from.EdPriv, sigInput(vault, from.Dev, to, id, tm, ephPub[:], nonce[:], ct))
	return json.Marshal(Envelope{V: 1, From: from.Dev, To: to, ID: id, Time: tm,
		Eph: kcrypto.B64(ephPub[:]), Nonce: kcrypto.B64(nonce[:]), CT: kcrypto.B64(ct), Sig: kcrypto.B64(sig)})
}

// Open verifies and decrypts line; id is the signed envelope id (the relay path id is not signed). senderEd returns the Ed25519 key of an allowed sender (nil = reject).
func Open(vault, self string, selfXPriv [32]byte, line []byte, senderEd func(dev string) ed25519.PublicKey) (from, id string, t time.Time, plaintext []byte, err error) {
	var e Envelope
	if err := Strict(line, &e); err != nil {
		return "", "", time.Time{}, nil, bad("json: %v", err)
	}
	if e.V != 1 {
		return "", "", time.Time{}, nil, bad("version %d", e.V)
	}
	if e.To != self {
		return "", "", time.Time{}, nil, bad("not addressed to this device")
	}
	var pub ed25519.PublicKey
	if senderEd != nil {
		pub = senderEd(e.From)
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", "", time.Time{}, nil, bad("unknown sender")
	}
	eph, err1 := kcrypto.UnB64(e.Eph)
	nonce, err2 := kcrypto.UnB64(e.Nonce)
	ct, err3 := kcrypto.UnB64(e.CT)
	sig, err4 := kcrypto.UnB64(e.Sig)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(eph) != 32 || len(nonce) != 12 || len(sig) != ed25519.SignatureSize {
		return "", "", time.Time{}, nil, bad("field encoding")
	}
	if len(e.ID) != 22 || len(ct) < 16 {
		return "", "", time.Time{}, nil, bad("field size")
	}
	t, terr := time.Parse(timeFmt, e.Time)
	if terr != nil || t.UTC().Format(timeFmt) != e.Time {
		return "", "", time.Time{}, nil, bad("time")
	}
	if !ed25519.Verify(pub, sigInput(vault, e.From, e.To, e.ID, e.Time, eph, nonce, ct), sig) {
		return "", "", time.Time{}, nil, bad("signature")
	}
	selfPub := kcrypto.X25519Public(selfXPriv)
	shared, xerr := curve25519.X25519(selfXPriv[:], eph)
	if xerr != nil {
		return "", "", time.Time{}, nil, bad("x25519")
	}
	info := msgInfo(vault, e.From, e.To, e.ID, eph, selfPub[:])
	a, gerr := gcm(kcrypto.HKDF(shared, info, 32))
	if gerr != nil {
		return "", "", time.Time{}, nil, bad("cipher")
	}
	pt, derr := a.Open(nil, nonce, ct, info)
	if derr != nil {
		return "", "", time.Time{}, nil, bad("decrypt")
	}
	return e.From, e.ID, t.UTC(), pt, nil
}
