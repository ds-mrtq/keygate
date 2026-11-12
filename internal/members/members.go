// Package members implements owner-signed membership events (DESIGN.md sec 4.2)
// and the replay that turns them into a membership state.
package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"

	"keygate/internal/kcrypto"
)

// Event types.
const (
	TypeGenesis = "genesis"
	TypeAdd     = "add"
	TypeRevoke  = "revoke"
	TypeEpoch   = "epoch"
	// TypeRevokeApprover revokes an approver device. Signed by an active key-holder device (not the
	// owner): an approver never held the vault key, so no epoch follows (DESIGN.md sec 4.2).
	TypeRevokeApprover = "revoke-approver"

	RecoveryRcpt = "recovery"
	MaxLineSize  = 1 << 20
	MaxLabel     = 64
)

// Errors. Callers map these to the vault-level typed errors.
var (
	ErrMalformed   = errors.New("keygate: malformed member event")
	ErrBadOwnerSig = errors.New("keygate: member event not signed by owner")
	ErrChain       = errors.New("keygate: member chain broken")
	ErrInvalid     = errors.New("keygate: invalid member event")
	ErrNoWrap      = errors.New("keygate: no key wrap for recipient")
)

// Event is one line of members.kgl.
type Event struct {
	V     int     `json:"v"`
	Vault string  `json:"vault"`
	N     uint64  `json:"n"`
	Prev  *string `json:"prev"`
	Type  string  `json:"type"`
	Body  string  `json:"body"` // base64 std of compact JSON
	Sig   string  `json:"sig"`
}

// GenesisBody is the body of a genesis event.
type GenesisBody struct {
	OwnerPub    string               `json:"owner_pub"`
	RecoveryPub string               `json:"recovery_pub"`
	ArgonSalt   string               `json:"argon_salt"`
	ArgonParams kcrypto.Argon2Params `json:"argon_params"`
	Created     string               `json:"created"`
}

// AddBody is the body of an add event (also the device registration payload).
type AddBody struct {
	Dev   string `json:"dev"`
	Label string `json:"label"`
	EdPub string `json:"ed_pub"`
	XPub  string `json:"x_pub"`
	Role  string `json:"role,omitempty"`
}

// RoleApprover marks a device that only signs approvals and commands; it
// never receives a vault-key wrap and never writes records.
const RoleApprover = "approver"

// RevokeBody is the body of a revoke event.
type RevokeBody struct {
	Dev     string `json:"dev"`
	Reason  string `json:"reason"`
	LastSeq uint64 `json:"last_seq"`
	// LastHash is the record_hash of the revoked device's record at LastSeq ("" iff LastSeq == 0).
	LastHash string `json:"last_hash"`
}

// RevokeApproverBody is the body of a revoke-approver event; By is the signing key-holder device.
type RevokeApproverBody struct {
	Dev    string `json:"dev"`
	By     string `json:"by"`
	Reason string `json:"reason"`
}

// EpochBody is the body of an epoch event.
type EpochBody struct {
	Epoch uint64         `json:"epoch"`
	Wraps []kcrypto.Wrap `json:"wraps"`
}

// Canonical returns the signed byte string.
func (e *Event) Canonical() ([]byte, error) {
	body, err := kcrypto.UnB64(e.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: body", ErrMalformed)
	}
	return kcrypto.NewEnc(kcrypto.LabelMember).U64(uint64(e.V)).LPS(e.Vault).U64(e.N).
		LPOpt(e.Prev).LPS(e.Type).LP(body).Bytes(), nil
}

// Sign signs with the owner key.
func (e *Event) Sign(owner ed25519.PrivateKey) error {
	c, err := e.Canonical()
	if err != nil {
		return err
	}
	e.Sig = kcrypto.B64(ed25519.Sign(owner, c))
	return nil
}

// Verify checks the owner signature.
func (e *Event) Verify(ownerPub ed25519.PublicKey) error {
	c, err := e.Canonical()
	if err != nil || len(ownerPub) != ed25519.PublicKeySize {
		return ErrBadOwnerSig
	}
	sig, err := kcrypto.UnB64(e.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ownerPub, c, sig) {
		return ErrBadOwnerSig
	}
	return nil
}

// Hash returns "sha256:" + hex(sha256(canonical || sig)).
func (e *Event) Hash() (string, error) {
	c, err := e.Canonical()
	if err != nil {
		return "", err
	}
	sig, err := kcrypto.UnB64(e.Sig)
	if err != nil {
		return "", fmt.Errorf("%w: sig", ErrMalformed)
	}
	return kcrypto.SHA256Ref(c, sig), nil
}

// Marshal returns the JSON line.
func (e *Event) Marshal() ([]byte, error) { return json.Marshal(e) }

// Parse decodes one members.kgl line (structure only; no signature check).
func Parse(line []byte) (*Event, error) {
	if len(line) == 0 || len(line) > MaxLineSize {
		return nil, fmt.Errorf("%w: size", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var e Event
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("%w: json", ErrMalformed)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	if e.V != 1 || !kcrypto.ValidVaultID(e.Vault) {
		return nil, fmt.Errorf("%w: header", ErrMalformed)
	}
	if (e.N == 0) != (e.Prev == nil) || (e.Prev != nil && !kcrypto.IsHashRef(*e.Prev)) {
		return nil, fmt.Errorf("%w: prev", ErrMalformed)
	}
	switch e.Type {
	case TypeGenesis, TypeAdd, TypeRevoke, TypeEpoch, TypeRevokeApprover:
	default:
		return nil, fmt.Errorf("%w: type", ErrMalformed)
	}
	if _, err := kcrypto.UnB64(e.Body); err != nil {
		return nil, fmt.Errorf("%w: body", ErrMalformed)
	}
	if s, err := kcrypto.UnB64(e.Sig); err != nil || len(s) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: sig", ErrMalformed)
	}
	if re, err := json.Marshal(&e); err != nil || !bytes.Equal(re, line) {
		return nil, fmt.Errorf("%w: non-canonical encoding", ErrMalformed)
	}
	return &e, nil
}

// DecodeBody strictly decodes the event body into v.
func (e *Event) DecodeBody(v any) error {
	raw, err := kcrypto.UnB64(e.Body)
	if err != nil {
		return fmt.Errorf("%w: body", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: body json", ErrMalformed)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: body trailing data", ErrMalformed)
	}
	return nil
}

// New builds and signs the event with index n following prev (nil for genesis). The key is the
// owner key, or the signing device's key for TypeRevokeApprover.
func New(vault string, n uint64, prev *Event, typ string, body any, owner ed25519.PrivateKey) (*Event, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	e := &Event{V: 1, Vault: vault, N: n, Type: typ, Body: kcrypto.B64(raw)}
	if prev != nil {
		h, err := prev.Hash()
		if err != nil {
			return nil, err
		}
		e.Prev = &h
	}
	if err := e.Sign(owner); err != nil {
		return nil, err
	}
	return e, nil
}

// Recipient is a vault-key wrap target.
type Recipient struct {
	ID   string // device id or RecoveryRcpt
	XPub [32]byte
}

// NewEpochBody wraps vaultKey for every recipient.
func NewEpochBody(vault string, epoch uint64, vaultKey []byte, rcpts []Recipient) (EpochBody, error) {
	b := EpochBody{Epoch: epoch}
	for _, r := range rcpts {
		w, err := kcrypto.WrapKey(vault, epoch, r.ID, r.XPub, vaultKey)
		if err != nil {
			return EpochBody{}, err
		}
		b.Wraps = append(b.Wraps, w)
	}
	return b, nil
}

// Device is one member as of the replayed state.
type Device struct {
	ID       string
	Label    string
	EdPub    ed25519.PublicKey
	XPub     [32]byte
	AddedN   uint64
	Revoked  bool
	Role     string
	LastSeq  uint64 // highest accepted seq once revoked
	LastHash string // required hash of the record at LastSeq ("" when LastSeq == 0)
}

// State is the membership state after replaying events 0..Count-1.
type State struct {
	Vault       string
	OwnerPub    ed25519.PublicKey
	RecoveryPub [32]byte
	ArgonSalt   []byte
	ArgonParams kcrypto.Argon2Params
	Created     string
	Devices     map[string]*Device
	Epoch       uint64
	Wraps       map[uint64]map[string]kcrypto.Wrap
	Count       uint64 // number of events applied; next expected n
	Head        string // hash of last event ("" before genesis)
	GenesisHash string // hash of event 0

	PendingEpoch bool // a revoke awaits its epoch event
}

// NewState returns an empty state awaiting genesis.
func NewState() *State {
	return &State{Devices: map[string]*Device{}, Wraps: map[uint64]map[string]kcrypto.Wrap{}}
}

// Clone deep-copies the state.
func (s *State) Clone() *State {
	c := *s
	c.OwnerPub = append(ed25519.PublicKey(nil), s.OwnerPub...)
	c.ArgonSalt = append([]byte(nil), s.ArgonSalt...)
	c.Devices = make(map[string]*Device, len(s.Devices))
	for k, d := range s.Devices {
		dc := *d
		dc.EdPub = append(ed25519.PublicKey(nil), d.EdPub...)
		c.Devices[k] = &dc
	}
	c.Wraps = make(map[uint64]map[string]kcrypto.Wrap, len(s.Wraps))
	for e, m := range s.Wraps {
		mc := make(map[string]kcrypto.Wrap, len(m))
		for k, w := range m {
			mc[k] = w
		}
		c.Wraps[e] = mc
	}
	return &c
}

// Replay applies all lines in order and returns the final state.
func Replay(lines [][]byte) (*State, error) {
	s := NewState()
	for i, l := range lines {
		e, err := Parse(l)
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}
		if err := s.Apply(e); err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}
	}
	return s, nil
}

// Active lists non-revoked devices sorted by id.
func (s *State) Active() []*Device {
	var out []*Device
	for _, d := range s.Devices {
		if !d.Revoked {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// KeyHolders lists active devices that hold (wraps of) the vault key: Active minus approvers.
func (s *State) KeyHolders() []*Device {
	var out []*Device
	for _, d := range s.Active() {
		if d.Role != RoleApprover {
			out = append(out, d)
		}
	}
	return out
}

// Approvers lists active approver devices sorted by id.
func (s *State) Approvers() []*Device {
	var out []*Device
	for _, d := range s.Active() {
		if d.Role == RoleApprover {
			out = append(out, d)
		}
	}
	return out
}

// Apply validates e as the next event (owner signature, chain, semantics) and updates the state.
func (s *State) Apply(e *Event) error {
	if e.N != s.Count {
		return fmt.Errorf("%w: expected n=%d got %d", ErrChain, s.Count, e.N)
	}
	if s.Count > 0 {
		if e.Vault != s.Vault {
			return fmt.Errorf("%w: vault mismatch", ErrInvalid)
		}
		if e.Prev == nil || *e.Prev != s.Head {
			return fmt.Errorf("%w: prev hash mismatch", ErrChain)
		}
	}
	if s.PendingEpoch && e.Type != TypeEpoch {
		return fmt.Errorf("%w: revoke must be followed by epoch", ErrInvalid)
	}
	switch e.Type {
	case TypeGenesis:
		if e.N != 0 {
			return fmt.Errorf("%w: genesis only at n=0", ErrInvalid)
		}
		var b GenesisBody
		if err := e.DecodeBody(&b); err != nil {
			return err
		}
		owner, err1 := kcrypto.UnB64(b.OwnerPub)
		rec, err2 := kcrypto.UnB64(b.RecoveryPub)
		salt, err3 := kcrypto.UnB64(b.ArgonSalt)
		if err1 != nil || err2 != nil || err3 != nil || len(owner) != 32 || len(rec) != 32 || len(salt) < 16 || b.ArgonParams.Validate() != nil {
			return fmt.Errorf("%w: genesis body", ErrInvalid)
		}
		if err := e.Verify(ed25519.PublicKey(owner)); err != nil {
			return err
		}
		s.Vault, s.OwnerPub, s.ArgonSalt, s.ArgonParams, s.Created = e.Vault, owner, salt, b.ArgonParams, b.Created
		copy(s.RecoveryPub[:], rec)
	case TypeRevokeApprover:
		if s.Count == 0 {
			return fmt.Errorf("%w: first event must be genesis", ErrInvalid)
		}
		if err := s.applyRevokeApprover(e); err != nil {
			return err
		}
	default:
		if s.Count == 0 {
			return fmt.Errorf("%w: first event must be genesis", ErrInvalid)
		}
		if err := e.Verify(s.OwnerPub); err != nil {
			return err
		}
		var err error
		switch e.Type {
		case TypeAdd:
			err = s.applyAdd(e)
		case TypeRevoke:
			err = s.applyRevoke(e)
		case TypeEpoch:
			err = s.applyEpoch(e)
		default:
			err = fmt.Errorf("%w: type", ErrInvalid)
		}
		if err != nil {
			return err
		}
	}
	h, err := e.Hash()
	if err != nil {
		return err
	}
	s.Head = h
	if e.N == 0 {
		s.GenesisHash = h
	}
	s.Count++
	return nil
}

func (s *State) applyAdd(e *Event) error {
	var b AddBody
	if err := e.DecodeBody(&b); err != nil {
		return err
	}
	ed, err1 := kcrypto.UnB64(b.EdPub)
	x, err2 := kcrypto.UnB64(b.XPub)
	if !kcrypto.ValidDeviceID(b.Dev) || err1 != nil || err2 != nil || len(ed) != 32 || len(x) != 32 || !validLabel(b.Label) {
		return fmt.Errorf("%w: add body", ErrInvalid)
	}
	if b.Role != "" && b.Role != RoleApprover {
		return fmt.Errorf("%w: add body role", ErrInvalid)
	}
	if _, dup := s.Devices[b.Dev]; dup {
		return fmt.Errorf("%w: device already exists", ErrInvalid)
	}
	d := &Device{ID: b.Dev, Label: b.Label, EdPub: ed, AddedN: e.N, Role: b.Role}
	copy(d.XPub[:], x)
	s.Devices[b.Dev] = d
	return nil
}

func validLabel(l string) bool {
	if l == "" || len(l) > MaxLabel || !utf8.ValidString(l) {
		return false
	}
	for _, r := range l {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (s *State) applyRevoke(e *Event) error {
	var b RevokeBody
	if err := e.DecodeBody(&b); err != nil {
		return err
	}
	d, ok := s.Devices[b.Dev]
	if !ok || d.Revoked {
		return fmt.Errorf("%w: revoke target not an active device", ErrInvalid)
	}
	if len(b.Reason) > 256 || !utf8.ValidString(b.Reason) {
		return fmt.Errorf("%w: revoke reason", ErrInvalid)
	}
	if (b.LastSeq == 0) != (b.LastHash == "") || (b.LastHash != "" && !kcrypto.IsHashRef(b.LastHash)) {
		return fmt.Errorf("%w: revoke last_seq/last_hash", ErrInvalid)
	}
	d.Revoked, d.LastSeq, d.LastHash = true, b.LastSeq, b.LastHash
	s.PendingEpoch = true
	return nil
}

// applyRevokeApprover checks the signer (an active key-holder device, by its own key) and the
// target (an active approver) and marks the target revoked. No epoch is pending afterwards.
func (s *State) applyRevokeApprover(e *Event) error {
	var b RevokeApproverBody
	if err := e.DecodeBody(&b); err != nil {
		return err
	}
	// The body must be byte-canonical (Go matches JSON keys case-insensitively; the relay and the
	// PWA would read another key than we do).
	if raw, _ := kcrypto.UnB64(e.Body); !bytes.Equal(mustJSON(b), raw) {
		return fmt.Errorf("%w: non-canonical revoke-approver body", ErrMalformed)
	}
	by, ok := s.Devices[b.By]
	if !ok || by.Revoked || by.Role == RoleApprover {
		return fmt.Errorf("%w: revoke-approver signer not an active key holder", ErrInvalid)
	}
	if err := e.Verify(by.EdPub); err != nil {
		return err
	}
	d, ok := s.Devices[b.Dev]
	if !ok || d.Revoked || d.Role != RoleApprover {
		return fmt.Errorf("%w: revoke-approver target not an active approver", ErrInvalid)
	}
	if len(b.Reason) > 256 || !utf8.ValidString(b.Reason) {
		return fmt.Errorf("%w: revoke reason", ErrInvalid)
	}
	d.Revoked = true
	return nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (s *State) applyEpoch(e *Event) error {
	var b EpochBody
	if err := e.DecodeBody(&b); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, w := range b.Wraps {
		if err := w.Validate(); err != nil {
			return fmt.Errorf("%w: wrap", ErrInvalid)
		}
		if seen[w.Rcpt] {
			return fmt.Errorf("%w: duplicate wrap recipient", ErrInvalid)
		}
		seen[w.Rcpt] = true
		if w.Rcpt != RecoveryRcpt {
			d, ok := s.Devices[w.Rcpt]
			if !ok || d.Revoked {
				return fmt.Errorf("%w: wrap for non-member", ErrInvalid)
			}
			if d.Role == RoleApprover {
				return fmt.Errorf("%w: wrap for approver", ErrInvalid)
			}
		}
	}
	switch {
	case b.Epoch == s.Epoch+1:
		kh := s.KeyHolders()
		want := len(kh) + 1
		if len(b.Wraps) != want || !seen[RecoveryRcpt] {
			return fmt.Errorf("%w: new epoch must wrap for every active device and recovery", ErrInvalid)
		}
		for _, d := range kh {
			if !seen[d.ID] {
				return fmt.Errorf("%w: new epoch must wrap for every active device and recovery", ErrInvalid)
			}
		}
		s.Wraps[b.Epoch] = map[string]kcrypto.Wrap{}
		s.Epoch = b.Epoch
		s.PendingEpoch = false
	case b.Epoch == s.Epoch && b.Epoch > 0 && !s.PendingEpoch:
		for _, w := range b.Wraps {
			if _, dup := s.Wraps[b.Epoch][w.Rcpt]; dup {
				return fmt.Errorf("%w: recipient already has a wrap", ErrInvalid)
			}
		}
	default:
		return fmt.Errorf("%w: epoch number", ErrInvalid)
	}
	for _, w := range b.Wraps {
		s.Wraps[b.Epoch][w.Rcpt] = w
	}
	return nil
}

// UnwrapKey recovers the vault key of epoch for recipient rcpt using its private key.
func (s *State) UnwrapKey(epoch uint64, rcpt string, priv [32]byte) ([]byte, error) {
	w, ok := s.Wraps[epoch][rcpt]
	if !ok {
		return nil, ErrNoWrap
	}
	return kcrypto.UnwrapKey(s.Vault, epoch, w, priv)
}
