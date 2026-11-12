// Package record implements the item record format (DESIGN.md sec 4.1).
package record

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"keygate/internal/kcrypto"
)

// Limits protecting parsers from hostile input.
const (
	MaxLineSize = 1 << 20
	MaxMerge    = 64
	MaxCTSize   = 512 << 10
	OpPut       = "put"
	OpTombstone = "tombstone"
	CurrentVer  = 1
	sigSize     = ed25519.SignatureSize
	nonceSize   = kcrypto.NonceSize
	minCTSize   = 16
)

// ErrMalformed is returned by Parse for any structural problem.
var ErrMalformed = errors.New("keygate: malformed record")

// Record is one signed, encrypted item version.
type Record struct {
	V      int      `json:"v"`
	Vault  string   `json:"vault"`
	Item   string   `json:"item"`
	Parent *string  `json:"parent"`
	Merge  []string `json:"merge,omitempty"`
	Dev    string   `json:"dev"`
	Seq    uint64   `json:"seq"`
	Prev   *string  `json:"prev"`
	Epoch  uint64   `json:"epoch"`
	Op     string   `json:"op"`
	Nonce  string   `json:"nonce"`
	CT     string   `json:"ct"`
	Sig    string   `json:"sig"`
}

// Plain is the plaintext sealed in ct. Tombstones carry only Name.
type Plain struct {
	Name    string   `json:"name"`
	Value   string   `json:"value,omitempty"`
	Desc    string   `json:"desc,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	Env     string   `json:"env,omitempty"`
	Kind    string   `json:"kind,omitempty"`
	EnvName string   `json:"env_name,omitempty"`
	TNS     string   `json:"tns_alias,omitempty"`
	User    string   `json:"user,omitempty"`
	FileExt string   `json:"file_ext,omitempty"`
}

func ptr(s string) *string { return &s }

// StrPtr returns a pointer to s (helper for Parent/Prev).
func StrPtr(s string) *string { return ptr(s) }

// Canonical returns the signed byte string.
func (r *Record) Canonical() ([]byte, error) {
	nonce, err := kcrypto.UnB64(r.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce", ErrMalformed)
	}
	ct, err := kcrypto.UnB64(r.CT)
	if err != nil {
		return nil, fmt.Errorf("%w: ct", ErrMalformed)
	}
	e := kcrypto.NewEnc(kcrypto.LabelRecord).
		U64(uint64(r.V)).LPS(r.Vault).LPS(r.Item).LPOpt(r.Parent).
		U64(uint64(len(r.Merge)))
	for _, m := range r.Merge {
		e.LPS(m)
	}
	e.LPS(r.Dev).U64(r.Seq).LPOpt(r.Prev).U64(r.Epoch).LPS(r.Op).LP(nonce).LP(ct)
	return e.Bytes(), nil
}

// Sign sets Sig using the device Ed25519 key.
func (r *Record) Sign(priv ed25519.PrivateKey) error {
	c, err := r.Canonical()
	if err != nil {
		return err
	}
	r.Sig = kcrypto.B64(ed25519.Sign(priv, c))
	return nil
}

// Verify checks the signature against the device public key.
func (r *Record) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return kcrypto.ErrBadSignature
	}
	c, err := r.Canonical()
	if err != nil {
		return kcrypto.ErrBadSignature
	}
	sig, err := kcrypto.UnB64(r.Sig)
	if err != nil || len(sig) != sigSize || !ed25519.Verify(pub, c, sig) {
		return kcrypto.ErrBadSignature
	}
	return nil
}

// Hash returns "sha256:" + hex(sha256(canonical || sig)).
func (r *Record) Hash() (string, error) {
	c, err := r.Canonical()
	if err != nil {
		return "", err
	}
	sig, err := kcrypto.UnB64(r.Sig)
	if err != nil {
		return "", fmt.Errorf("%w: sig", ErrMalformed)
	}
	return kcrypto.SHA256Ref(c, sig), nil
}

// AAD is the additional data bound to ct.
func (r *Record) AAD() []byte {
	return kcrypto.NewEnc(kcrypto.LabelRecord).
		LPS(r.Vault).LPS(r.Item).LPOpt(r.Parent).U64(r.Epoch).LPS(r.Dev).U64(r.Seq).Bytes()
}

// EncryptWithNonce seals p into Nonce/CT using the item key of (Vault, Epoch, Item).
// Vault, Item, Parent, Epoch, Dev and Seq must already be set.
func (r *Record) EncryptWithNonce(vaultKey []byte, nonce [24]byte, p Plain) error {
	if r.Op == OpTombstone {
		p = Plain{Name: p.Name}
	}
	pt, err := json.Marshal(p)
	if err != nil {
		return err
	}
	key := kcrypto.ItemKey(vaultKey, r.Vault, r.Epoch, r.Item)
	ct, err := kcrypto.Seal(key, nonce[:], pt, r.AAD())
	if err != nil {
		return err
	}
	r.Nonce, r.CT = kcrypto.B64(nonce[:]), kcrypto.B64(ct)
	return nil
}

// Encrypt is EncryptWithNonce with a random nonce.
func (r *Record) Encrypt(vaultKey []byte, p Plain) error {
	var n [24]byte
	if _, err := io.ReadFull(rand.Reader, n[:]); err != nil {
		return err
	}
	return r.EncryptWithNonce(vaultKey, n, p)
}

// Decrypt opens ct with the vault key of r.Epoch.
func (r *Record) Decrypt(vaultKey []byte) (Plain, error) {
	nonce, err1 := kcrypto.UnB64(r.Nonce)
	ct, err2 := kcrypto.UnB64(r.CT)
	if err1 != nil || err2 != nil {
		return Plain{}, kcrypto.ErrDecrypt
	}
	key := kcrypto.ItemKey(vaultKey, r.Vault, r.Epoch, r.Item)
	pt, err := kcrypto.Open(key, nonce, ct, r.AAD())
	if err != nil {
		return Plain{}, err
	}
	var p Plain
	dec := json.NewDecoder(bytes.NewReader(pt))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Plain{}, kcrypto.ErrDecrypt
	}
	if r.Op == OpTombstone && p.Value != "" {
		return Plain{}, kcrypto.ErrDecrypt
	}
	return p, nil
}

// Marshal returns the JSON line (no trailing newline).
func (r *Record) Marshal() ([]byte, error) { return json.Marshal(r) }

// Parse decodes and strictly validates one record line. It does not verify the signature.
func Parse(line []byte) (*Record, error) {
	if len(line) == 0 || len(line) > MaxLineSize {
		return nil, fmt.Errorf("%w: size", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var r Record
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: json", ErrMalformed)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	// One signed object, one line encoding: rejects duplicate/case-variant keys and odd escapes.
	if re, err := json.Marshal(&r); err != nil || !bytes.Equal(re, line) {
		return nil, fmt.Errorf("%w: non-canonical encoding", ErrMalformed)
	}
	return &r, nil
}

func (r *Record) validate() error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrMalformed, what) }
	if r.V != CurrentVer {
		return bad("version")
	}
	if !kcrypto.ValidVaultID(r.Vault) {
		return bad("vault id")
	}
	if !kcrypto.ValidItemID(r.Item) {
		return bad("item id")
	}
	if !kcrypto.ValidDeviceID(r.Dev) {
		return bad("dev id")
	}
	if r.Parent != nil && !kcrypto.IsHashRef(*r.Parent) {
		return bad("parent")
	}
	if len(r.Merge) > MaxMerge {
		return bad("merge size")
	}
	for _, m := range r.Merge {
		if !kcrypto.IsHashRef(m) {
			return bad("merge hash")
		}
	}
	if len(r.Merge) > 0 && r.Parent == nil {
		return bad("merge without parent")
	}
	if r.Seq < 1 {
		return bad("seq")
	}
	if (r.Seq == 1) != (r.Prev == nil) {
		return bad("prev/seq")
	}
	if r.Prev != nil && !kcrypto.IsHashRef(*r.Prev) {
		return bad("prev")
	}
	if r.Epoch < 1 {
		return bad("epoch")
	}
	if r.Op != OpPut && r.Op != OpTombstone {
		return bad("op")
	}
	n, err := kcrypto.UnB64(r.Nonce)
	if err != nil || len(n) != nonceSize {
		return bad("nonce")
	}
	ct, err := kcrypto.UnB64(r.CT)
	if err != nil || len(ct) < minCTSize || len(ct) > MaxCTSize {
		return bad("ct")
	}
	sig, err := kcrypto.UnB64(r.Sig)
	if err != nil || len(sig) != sigSize {
		return bad("sig")
	}
	return nil
}
