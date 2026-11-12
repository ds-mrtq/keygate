// Package checkpoint implements device-signed checkpoints (DESIGN.md sec 4.3).
package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"keygate/internal/kcrypto"
)

// ErrMalformed is returned by Parse.
var ErrMalformed = errors.New("keygate: malformed checkpoint")

const maxSize = 1 << 20

// Checkpoint states what a device has seen.
type Checkpoint struct {
	V        int               `json:"v"`
	Vault    string            `json:"vault"`
	Dev      string            `json:"dev"`
	Time     string            `json:"time"`
	MembersN uint64            `json:"members_n"`
	Seen     map[string]uint64 `json:"seen"`
	Sig      string            `json:"sig"`
}

// Canonical returns the signed byte string (seen sorted by dev).
func (c *Checkpoint) Canonical() []byte {
	e := kcrypto.NewEnc(kcrypto.LabelCheckpoint).U64(uint64(c.V)).LPS(c.Vault).LPS(c.Dev).LPS(c.Time).U64(c.MembersN)
	devs := make([]string, 0, len(c.Seen))
	for d := range c.Seen {
		devs = append(devs, d)
	}
	sort.Strings(devs)
	for _, d := range devs {
		e.LPS(d).U64(c.Seen[d])
	}
	return e.Bytes()
}

// Sign signs with the device key.
func (c *Checkpoint) Sign(priv ed25519.PrivateKey) {
	c.Sig = kcrypto.B64(ed25519.Sign(priv, c.Canonical()))
}

// Verify checks the device signature.
func (c *Checkpoint) Verify(pub ed25519.PublicKey) error {
	sig, err := kcrypto.UnB64(c.Sig)
	if err != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, c.Canonical(), sig) {
		return kcrypto.ErrBadSignature
	}
	return nil
}

// Marshal returns the JSON body.
func (c *Checkpoint) Marshal() ([]byte, error) { return json.Marshal(c) }

// Total is members_n plus the sum of seen seqs (used to pick the newer of two checkpoints).
func (c *Checkpoint) Total() uint64 {
	t := c.MembersN
	for _, s := range c.Seen {
		t += s
	}
	return t
}

// Parse decodes and validates a checkpoint (no signature check).
func Parse(b []byte) (*Checkpoint, error) {
	if len(b) == 0 || len(b) > maxSize {
		return nil, fmt.Errorf("%w: size", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Checkpoint
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: json", ErrMalformed)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	if c.V != 1 || !kcrypto.ValidVaultID(c.Vault) || !kcrypto.ValidDeviceID(c.Dev) || c.Seen == nil {
		return nil, fmt.Errorf("%w: header", ErrMalformed)
	}
	for d := range c.Seen {
		if !kcrypto.ValidDeviceID(d) {
			return nil, fmt.Errorf("%w: seen dev", ErrMalformed)
		}
	}
	if s, err := kcrypto.UnB64(c.Sig); err != nil || len(s) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: sig", ErrMalformed)
	}
	if re, err := json.Marshal(&c); err != nil || !bytes.Equal(re, b) {
		return nil, fmt.Errorf("%w: non-canonical encoding", ErrMalformed)
	}
	return &c, nil
}
