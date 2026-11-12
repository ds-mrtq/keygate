// Package store is the local KeyGate vault: KG_HOME layout, append-only device log,
// verification on ingest, merge/conflicts, epoch re-encryption and local state.
package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"keygate/internal/fsx"
	"keygate/internal/kcrypto"
	"keygate/internal/members"
	"keygate/internal/recovery"
	"keygate/internal/transport"
)

// VaultConfig is vault.json (public).
type VaultConfig struct {
	Vault    string        `json:"vault"`
	RelayURL string        `json:"relay_url,omitempty"`
	GitDir   string        `json:"git_dir,omitempty"`
	SyncDir  string        `json:"sync_dir,omitempty"`
	Oracle   *OracleConfig `json:"oracle,omitempty"`
}

// OracleConfig holds optional wallet tooling paths (DESIGN sec 10).
type OracleConfig struct {
	PkiJar   string `json:"pki_jar,omitempty"`
	Java     string `json:"java,omitempty"`
	TnsAdmin string `json:"tns_admin,omitempty"`
}

// Store is an opened KG_HOME bound to this device identity. Safe for concurrent use.
type Store struct {
	mu   sync.Mutex
	Home string
	ID   *Identity

	cfg       VaultConfig
	v         *view
	hw        map[string]uint64 // high-water seq confirmed against a channel
	hwMembers uint64            // member events confirmed against a channel
	keys      map[uint64][]byte // unwrapped vault keys by epoch
	chans     map[string]*chanState
	unlock    func()
}

// Close releases the cross-process lock on KG_HOME. Short-lived commands may skip it
// (a lock left by a dead process is detected as stale).
func (s *Store) Close() {
	if s.unlock != nil {
		s.unlock()
		s.unlock = nil
	}
}

// Paths inside KG_HOME.
func membersPath(home string) string  { return filepath.Join(home, "members.kgl") }
func logDir(home string) string       { return filepath.Join(home, "log") }
func logPath(home, dev string) string { return filepath.Join(logDir(home), dev+".kgl") }
func cpDir(home string) string        { return filepath.Join(home, "checkpoints") }
func cpPath(home, dev string) string  { return filepath.Join(cpDir(home), dev+".json") }
func localPath(home string) string    { return filepath.Join(home, "state", "local.json") }
func vaultPath(home string) string    { return filepath.Join(home, "vault.json") }

// Init creates a new vault in home: vault.json, genesis, add(this device), epoch 1.
// The caller must have saved the identity (SaveIdentity) and generated keys via recovery.NewSetup.
func Init(home, vault string, id *Identity, keys *recovery.Keys, salt []byte, params kcrypto.Argon2Params, created time.Time) (*Store, error) {
	if _, err := os.Stat(membersPath(home)); err == nil {
		return nil, ErrExists
	}
	if !kcrypto.ValidVaultID(vault) {
		return nil, errors.New("keygate: invalid vault id")
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	gen, err := members.New(vault, 0, nil, members.TypeGenesis, members.GenesisBody{
		OwnerPub: kcrypto.B64(keys.OwnerPub), RecoveryPub: kcrypto.B64(keys.RecoveryPub[:]),
		ArgonSalt: kcrypto.B64(salt), ArgonParams: params, Created: created.UTC().Format(time.RFC3339),
	}, keys.OwnerPriv)
	if err != nil {
		return nil, err
	}
	add, err := members.New(vault, 1, gen, members.TypeAdd, id.Public(), keys.OwnerPriv)
	if err != nil {
		return nil, err
	}
	vk := kcrypto.NewVaultKey()
	eb, err := members.NewEpochBody(vault, 1, vk, []members.Recipient{{ID: id.Dev, XPub: id.XPub}, {ID: members.RecoveryRcpt, XPub: keys.RecoveryPub}})
	if err != nil {
		return nil, err
	}
	ep, err := members.New(vault, 2, add, members.TypeEpoch, eb, keys.OwnerPriv)
	if err != nil {
		return nil, err
	}
	var lines [][]byte
	for _, e := range []*members.Event{gen, add, ep} {
		l, err := e.Marshal()
		if err != nil {
			return nil, err
		}
		lines = append(lines, l)
	}
	if err := writeJSON(vaultPath(home), VaultConfig{Vault: vault}); err != nil {
		return nil, err
	}
	if err := fsx.AppendLines(membersPath(home), lines...); err != nil {
		return nil, err
	}
	s := &Store{Home: home, ID: id, cfg: VaultConfig{Vault: vault}, hw: map[string]uint64{}, keys: map[uint64][]byte{}, chans: map[string]*chanState{}}
	if err := s.saveLocal(); err != nil {
		return nil, err
	}
	return Open(home, id)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsx.WriteAtomic(path, b)
}

// ReadConfig reads and validates vault.json in home (public data, no keys needed).
func ReadConfig(home string) (VaultConfig, error) {
	var c VaultConfig
	b, err := os.ReadFile(vaultPath(home))
	if err != nil {
		return c, fmt.Errorf("keygate: read vault.json: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil || !kcrypto.ValidVaultID(c.Vault) {
		return c, errors.New("keygate: vault.json corrupt")
	}
	return c, nil
}

// Open loads and fully re-verifies KG_HOME (signatures, chains, local high-water marks).
func Open(home string, id *Identity) (*Store, error) {
	return open(home, id, false)
}

func open(home string, id *Identity, allowEmpty bool) (st *Store, err error) {
	s := &Store{Home: home, ID: id, hw: map[string]uint64{}, keys: map[uint64][]byte{}, chans: map[string]*chanState{}}
	if s.cfg, err = ReadConfig(home); err != nil {
		return nil, err
	}
	if s.unlock, err = fsx.Lock(filepath.Join(home, "lock")); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	s.v = newView(s.cfg.Vault)
	mlines, err := readRepair(membersPath(home))
	if err != nil {
		return nil, err
	}
	if len(mlines) == 0 && !allowEmpty {
		return nil, errors.New("keygate: members.kgl missing or empty")
	}
	if _, _, err := verifyMembers(s.v, mlines); err != nil {
		return nil, err
	}
	logs := map[string][][]byte{}
	ents, err := os.ReadDir(logDir(home))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".kgl") {
			continue
		}
		lines, err := readRepair(filepath.Join(logDir(home), name))
		if err != nil {
			return nil, err
		}
		logs[strings.TrimSuffix(name, ".kgl")] = lines
	}
	if _, _, err := verifyLogs(s.v, logs); err != nil {
		return nil, err
	}
	if err := clampRevoked(s.v); err != nil {
		return nil, err
	}
	if err := s.loadLocal(); err != nil {
		return nil, err
	}
	if err := s.loadChannels(); err != nil {
		return nil, err
	}
	s.clampHW()
	if s.hwMembers > s.v.ms.Count {
		return nil, wrapErr(ErrRollback, "local members.kgl is shorter than the recorded high-water")
	}
	for d, hw := range s.hw {
		if hw > s.v.lastSeq(d) {
			return nil, wrapErr(ErrRollback, "local log of %s is shorter than the recorded high-water", d)
		}
	}
	for c, cs := range s.chans {
		if cs.MembersN > s.v.ms.Count {
			return nil, wrapErr(ErrRollback, "local members.kgl is shorter than the high-water of channel %s", c)
		}
		for d, hw := range cs.HW {
			if hw > s.v.lastSeq(d) {
				return nil, wrapErr(ErrRollback, "local log of %s is shorter than the high-water of channel %s", d, c)
			}
		}
	}
	return s, nil
}

// readRepair reads a local append-only log, truncating a torn final line (with a warning).
func readRepair(path string) ([][]byte, error) {
	lines, repaired, err := fsx.ReadLinesRepair(path)
	if repaired {
		fmt.Fprintf(os.Stderr, "keygate: warning: truncated a torn final line in %s\n", filepath.Base(path))
	}
	return lines, err
}

// Vault returns the vault id.
func (s *Store) Vault() string { return s.cfg.Vault }

// Config returns a copy of vault.json.
func (s *Store) Config() VaultConfig { return s.cfg }

// SaveConfig rewrites vault.json (vault id is not changeable).
func (s *Store) SaveConfig(c VaultConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.Vault = s.cfg.Vault
	if err := writeJSON(vaultPath(s.Home), c); err != nil {
		return err
	}
	s.cfg = c
	return nil
}

// Members returns a snapshot copy of the membership state.
func (s *Store) Members() *members.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v.ms.Clone()
}

// Epoch returns the current vault-key epoch.
func (s *Store) Epoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v.ms.Epoch
}

// ---- fingerprint and fork detection ----

func fingerprintOf(v *view) string {
	e := kcrypto.NewEnc("").LPS(v.ms.Head)
	devs := make([]string, 0, len(v.logs))
	for d, l := range v.logs {
		if len(l.recs) > 0 {
			devs = append(devs, d)
		}
	}
	sort.Strings(devs)
	for _, d := range devs {
		l := v.logs[d]
		e.LPS(d).LPS(l.hashes[len(l.hashes)-1])
	}
	sum := sha256.Sum256(e.Bytes())
	return Words(sum[:])
}

// Words maps the first 6 bytes of sum to 6 words of the fixed 256-word list (8 bits per word),
// e.g. for device-request confirmation codes. sum must hold at least 6 bytes.
func Words(sum []byte) string {
	w := make([]string, 6)
	for i := range w {
		w[i] = wordList[sum[i]]
	}
	return strings.Join(w, " ")
}

// Fingerprint returns the 6-word fingerprint of the local verified state.
func (s *Store) Fingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fingerprintOf(s.v)
}

// ViewFingerprint verifies a full snapshot (pulled with an empty Since) from scratch against this
// vault's genesis and returns the fingerprint of the state that channel presents.
func (s *Store) ViewFingerprint(snap transport.Snapshot) (string, error) {
	s.mu.Lock()
	pin := s.v.mhash[0]
	vault := s.cfg.Vault
	s.mu.Unlock()
	v := newView(vault)
	v.pin = pin
	if _, _, err := verifyMembers(v, snap.Members); err != nil {
		return "", err
	}
	if _, _, err := verifyLogs(v, snap.Logs); err != nil {
		return "", err
	}
	if _, err := verifyCheckpoints(v, snap.Checkpoints); err != nil {
		return "", err
	}
	return fingerprintOf(v), nil
}

// ---- recovery ----

// Recover creates a fresh KG_HOME for a new device using the owner/recovery keys derived from
// master password + paper key. snap must be a full pull (empty Since) from a channel.
// It verifies the vault, opens the latest vault key with the recovery key, ingests everything
// and registers id as a new device (add + same-epoch wrap), pending push.
func Recover(home string, id *Identity, keys *recovery.Keys, snap transport.Snapshot, pin string) (st *Store, err error) {
	if _, e := os.Stat(membersPath(home)); e == nil {
		return nil, ErrExists
	}
	state, err := members.Replay(snap.Members)
	if err != nil {
		return nil, wrapErr(ErrBrokenChain, "members: %v", err)
	}
	if state.Count == 0 {
		return nil, errors.New("keygate: channel has no vault")
	}
	if !bytes.Equal(state.OwnerPub, keys.OwnerPub) || state.RecoveryPub != keys.RecoveryPub {
		return nil, ErrWrongKeys
	}
	if pin != "" && !pinMatches(pin, state) {
		return nil, ErrPin
	}
	vk, err := state.UnwrapKey(state.Epoch, members.RecoveryRcpt, keys.RecoveryPriv)
	if err != nil {
		return nil, ErrWrongKeys
	}
	st, err = bootstrap(home, id, state, snap)
	if err != nil {
		return nil, err
	}
	st.keys[state.Epoch] = vk
	if err = st.AddDevice(keys.OwnerPriv, id.Public()); err != nil {
		st.Close()
		cleanHome(home)
		return nil, err
	}
	return st, nil
}

// Join creates a fresh KG_HOME on a device that the owner has already added (event on the channel).
// snap must be a full pull (empty Since). The identity must be an active member, and the channel's
// genesis must match pin (the value `kg device add` / `kg status` printed on a trusted device):
// the channel is never trusted to define the vault.
func Join(home string, id *Identity, snap transport.Snapshot, pin string) (*Store, error) {
	if _, e := os.Stat(membersPath(home)); e == nil {
		return nil, ErrExists
	}
	state, err := members.Replay(snap.Members)
	if err != nil {
		return nil, wrapErr(ErrBrokenChain, "members: %v", err)
	}
	if pin == "" || !pinMatches(pin, state) {
		return nil, ErrPin
	}
	if d, ok := state.Devices[id.Dev]; !ok || d.Revoked {
		return nil, ErrNotMember
	}
	return bootstrap(home, id, state, snap)
}

func cleanHome(home string) {
	for _, p := range []string{membersPath(home), logDir(home), cpDir(home), filepath.Join(home, "state"), vaultPath(home)} {
		os.RemoveAll(p)
	}
}

// bootstrap writes the skeleton of a fresh home and ingests snap into it.
func bootstrap(home string, id *Identity, state *members.State, snap transport.Snapshot) (st *Store, err error) {
	defer func() {
		if err != nil {
			if st != nil {
				st.Close()
			}
			cleanHome(home)
		}
	}()
	if err = os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	if err = writeJSON(vaultPath(home), VaultConfig{Vault: state.Vault}); err != nil {
		return nil, err
	}
	seed := &Store{Home: home, ID: id, hw: map[string]uint64{}, cfg: VaultConfig{Vault: state.Vault}}
	if err = seed.saveLocal(); err != nil {
		return nil, err
	}
	st, err = open(home, id, true)
	if err != nil {
		return nil, err
	}
	if _, err = st.IngestFrom("", snap); err != nil {
		return nil, err
	}
	return st, nil
}

// lastMemberEvent parses the last member line.
func (s *Store) lastMemberEvent() (*members.Event, error) {
	return members.Parse(s.v.mlines[len(s.v.mlines)-1])
}

// appendMembers validates evs as the next events and persists them.
func (s *Store) appendMembers(evs ...*members.Event) error {
	v := s.v.clone()
	var lines [][]byte
	for _, e := range evs {
		l, err := e.Marshal()
		if err != nil {
			return err
		}
		if _, _, err := verifyMembers(v, [][]byte{l}); err != nil {
			return err
		}
		lines = append(lines, l)
	}
	if err := fsx.AppendLines(membersPath(s.Home), lines...); err != nil {
		return err
	}
	s.v = v
	return nil
}

func checkOwner(st *members.State, owner ed25519.PrivateKey) error {
	if len(owner) != ed25519.PrivateKeySize || !bytes.Equal(owner.Public().(ed25519.PublicKey), st.OwnerPub) {
		return ErrNotOwner
	}
	return nil
}
