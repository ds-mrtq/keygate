package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"keygate/internal/checkpoint"
	"keygate/internal/fsx"
	"keygate/internal/kcrypto"
	"keygate/internal/members"
	"keygate/internal/transport"
)

// ---- genesis pin ----

var pinEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenesisPinOf = first 15 bytes (120 bits) of sha256(genesis record_hash bytes || vault id),
// base32 upper without padding, groups of 4 joined by '-'.
func GenesisPinOf(vault, genesisHash string) string {
	raw, _ := hexDecodeRef(genesisHash)
	sum := sha256.Sum256(append(raw, []byte(vault)...))
	s := pinEnc.EncodeToString(sum[:15])
	var parts []string
	for len(s) > 0 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(parts, "-")
}

func hexDecodeRef(ref string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(ref, "sha256:"))
}

func normPin(p string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(p))
}

func pinMatches(pin string, st *members.State) bool {
	want := normPin(GenesisPinOf(st.Vault, st.GenesisHash))
	return hmac.Equal([]byte(normPin(pin)), []byte(want))
}

// GenesisPin returns the pin of this vault (shown by `kg device add` and `kg status`).
func (s *Store) GenesisPin() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return GenesisPinOf(s.cfg.Vault, s.v.ms.GenesisHash)
}

// ---- local state (MAC'd) ----

type localState struct {
	V        int               `json:"v"`
	MembersN uint64            `json:"members_n"`
	HW       map[string]uint64 `json:"hw"`
	MAC      string            `json:"mac"`
}

// chanState is the high-water of one sync channel (state/channels/<name>.json).
type chanState struct {
	MembersN uint64
	HW       map[string]uint64
}

type chanFile struct {
	V        int               `json:"v"`
	Channel  string            `json:"channel"`
	MembersN uint64            `json:"members_n"`
	HW       map[string]uint64 `json:"hw"`
	MAC      string            `json:"mac"`
}

var chanNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// LocalMacKey returns the key for MACing local state (seen, policy pin, audit):
// HKDF(device Ed25519 seed, "kg/v1/local-mac\0").
func (s *Store) LocalMacKey() []byte { return s.ID.LocalMacKey() }

// macInput binds kind, vault, device, channel and the counters.
func (s *Store) macInput(kind, channel string, membersN uint64, hw map[string]uint64) []byte {
	e := kcrypto.NewEnc(kcrypto.LabelLocalMac).LPS(kind).LPS(s.cfg.Vault).LPS(s.ID.Dev).LPS(channel).U64(membersN)
	devs := make([]string, 0, len(hw))
	for d := range hw {
		devs = append(devs, d)
	}
	sort.Strings(devs)
	for _, d := range devs {
		e.LPS(d).U64(hw[d])
	}
	return e.Bytes()
}

func (s *Store) sign(in []byte) string { return kcrypto.B64(kcrypto.MAC(s.LocalMacKey(), in)) }

func (s *Store) macOK(in []byte, mac string) bool {
	m, err := kcrypto.UnB64(mac)
	return err == nil && hmac.Equal(m, kcrypto.MAC(s.LocalMacKey(), in))
}

func (s *Store) saveLocal() error {
	ls := localState{V: 1, MembersN: s.hwMembers, HW: map[string]uint64{}}
	for d, h := range s.hw {
		ls.HW[d] = h
	}
	ls.MAC = s.sign(s.macInput("local", "", ls.MembersN, ls.HW))
	return writeJSON(localPath(s.Home), ls)
}

func (s *Store) loadLocal() error {
	b, err := os.ReadFile(localPath(s.Home))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLocalState, err)
	}
	var ls localState
	if err := json.Unmarshal(b, &ls); err != nil || ls.V != 1 || ls.HW == nil {
		return fmt.Errorf("%w: unreadable", ErrLocalState)
	}
	if !s.macOK(s.macInput("local", "", ls.MembersN, ls.HW), ls.MAC) {
		return fmt.Errorf("%w: MAC mismatch", ErrLocalState)
	}
	s.hw, s.hwMembers = ls.HW, ls.MembersN
	return nil
}

func chanPath(home, name string) string {
	return filepath.Join(home, "state", "channels", name+".json")
}

func (s *Store) saveChan(name string) error {
	cs := s.chans[name]
	cf := chanFile{V: 1, Channel: name, MembersN: cs.MembersN, HW: cs.HW}
	cf.MAC = s.sign(s.macInput("channel", name, cs.MembersN, cs.HW))
	return writeJSON(chanPath(s.Home, name), cf)
}

func (s *Store) loadChannels() error {
	ents, err := os.ReadDir(filepath.Join(s.Home, "state", "channels"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range ents {
		name := strings.TrimSuffix(e.Name(), ".json")
		if name == e.Name() || !chanNameRe.MatchString(name) {
			continue
		}
		b, err := os.ReadFile(chanPath(s.Home, name))
		if err != nil {
			return err
		}
		var cf chanFile
		if err := json.Unmarshal(b, &cf); err != nil || cf.V != 1 || cf.Channel != name || cf.HW == nil {
			return fmt.Errorf("%w: channel %s unreadable", ErrLocalState, name)
		}
		if !s.macOK(s.macInput("channel", name, cf.MembersN, cf.HW), cf.MAC) {
			return fmt.Errorf("%w: channel %s MAC mismatch", ErrLocalState, name)
		}
		s.chans[name] = &chanState{MembersN: cf.MembersN, HW: cf.HW}
	}
	return nil
}

// clampHW lowers high-water marks of revoked devices to their last_seq (records above it are never held).
func (s *Store) clampHW() {
	for id, d := range s.v.ms.Devices {
		if !d.Revoked {
			continue
		}
		if s.hw[id] > d.LastSeq {
			s.hw[id] = d.LastSeq
		}
		for _, cs := range s.chans {
			if cs.HW[id] > d.LastSeq {
				cs.HW[id] = d.LastSeq
			}
		}
	}
}

// cursor returns the confirmed high-water of channel ch ("" = the global one).
// Caller holds s.mu. A channel never synced before has an empty cursor ("not yet populated").
func (s *Store) cursor(ch string) (membersN uint64, hw map[string]uint64) {
	if ch == "" {
		return s.hwMembers, s.hw
	}
	if cs := s.chans[ch]; cs != nil {
		return cs.MembersN, cs.HW
	}
	return 0, nil
}

func (s *Store) bump(ch string, membersN uint64, hw map[string]uint64) error {
	if membersN > s.hwMembers {
		s.hwMembers = membersN
	}
	for d, h := range hw {
		if h > s.hw[d] {
			s.hw[d] = h
		}
	}
	if ch != "" {
		cs := s.chans[ch]
		if cs == nil {
			cs = &chanState{HW: map[string]uint64{}}
			s.chans[ch] = cs
		}
		if membersN > cs.MembersN {
			cs.MembersN = membersN
		}
		for d, h := range hw {
			if h > cs.HW[d] {
				cs.HW[d] = h
			}
		}
		if err := s.saveChan(ch); err != nil {
			return err
		}
	}
	return s.saveLocal()
}

func checkChan(ch string) error {
	if ch != "" && !chanNameRe.MatchString(ch) {
		return fmt.Errorf("keygate: invalid channel name %q", ch)
	}
	return nil
}

// ---- ingest ----

// IngestResult counts what an Ingest added.
type IngestResult struct {
	Members     int
	Records     int
	Checkpoints int
}

// Since is the pull cursor for channel ch. It deliberately re-requests the last confirmed line of
// every device on that channel (hw-1) so a channel that lost it is detected as ErrRollback.
// A channel never synced before gets an empty cursor (full pull).
func (s *Store) Since(ch string) transport.Since {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := transport.Since{Logs: map[string]uint64{}}
	m, hw := s.cursor(ch)
	if m > 0 {
		out.Members = int(m - 1)
	}
	for d, h := range hw {
		if h > 0 {
			out.Logs[d] = h - 1
		}
	}
	return out
}

// IngestFrom verifies a snapshot from channel ch as if the channel checked nothing, and only if
// everything passes appends the new lines to the local logs. On any error nothing is written.
// Records of a revoked device above its last_seq are dropped, not fatal.
func (s *Store) IngestFrom(ch string, snap transport.Snapshot) (IngestResult, error) {
	if err := checkChan(ch); err != nil {
		return IngestResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.v.clone()
	var res IngestResult
	freshM, seenM, err := verifyMembers(v, snap.Members)
	if err != nil {
		return res, err
	}
	if err := clampRevoked(v); err != nil {
		return res, err
	}
	freshL, maxSeq, err := verifyLogs(v, snap.Logs)
	if err != nil {
		return res, err
	}
	cm, chw := s.cursor(ch)
	if cm > 0 && seenM < cm {
		return res, wrapErr(ErrRollback, "channel has %d member events, high-water is %d", seenM, cm)
	}
	for d, hw := range chw {
		if dv, ok := v.ms.Devices[d]; ok && dv.Revoked && hw > dv.LastSeq {
			hw = dv.LastSeq
		}
		if hw > 0 && maxSeq[d] < hw {
			return res, wrapErr(ErrRollback, "channel holds %s up to seq %d, high-water is %d", d, maxSeq[d], hw)
		}
	}
	cps, err := verifyCheckpoints(v, snap.Checkpoints)
	if err != nil {
		return res, err
	}
	// commit
	if len(freshM) > 0 {
		if err := fsx.AppendLines(membersPath(s.Home), freshM...); err != nil {
			return res, err
		}
	}
	devs := make([]string, 0, len(freshL))
	for d := range freshL {
		devs = append(devs, d)
	}
	sort.Strings(devs)
	for _, d := range devs {
		if err := fsx.AppendLines(logPath(s.Home, d), freshL[d]...); err != nil {
			return res, err
		}
		res.Records += len(freshL[d])
	}
	for d, cp := range cps {
		if d == s.ID.Dev {
			continue
		}
		if old, err := os.ReadFile(cpPath(s.Home, d)); err == nil {
			if oc, err := checkpoint.Parse(old); err == nil && oc.Total() > cp.Total() {
				continue
			}
		}
		if err := fsx.WriteAtomic(cpPath(s.Home, d), snap.Checkpoints[d]); err != nil {
			return res, err
		}
		res.Checkpoints++
	}
	s.v = v
	res.Members = len(freshM)
	s.clampHW()
	return res, s.bump(ch, seenM, maxSeq)
}

// ---- pending push data ----

// PendingMembers returns member lines not yet confirmed on channel ch and the index of the first.
func (s *Store) PendingMembers(ch string) (first int, lines [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, _ := s.cursor(ch)
	first = int(m)
	if first > len(s.v.mlines) {
		first = len(s.v.mlines)
	}
	return first, append([][]byte(nil), s.v.mlines[first:]...)
}

// PendingOwnLines returns this device's log lines not yet confirmed on channel ch and the seq of the first.
func (s *Store) PendingOwnLines(ch string) (firstSeq uint64, lines [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, hw := s.cursor(ch)
	l := s.v.logs[s.ID.Dev]
	if l == nil {
		return 1, nil
	}
	h := hw[s.ID.Dev]
	return h + 1, append([][]byte(nil), l.lines[h:]...)
}

// MarkPushed records that channel ch now holds our log up to ownSeq and members up to membersN.
func (s *Store) MarkPushed(ch string, ownSeq, membersN uint64) error {
	if err := checkChan(ch); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ownSeq > s.v.lastSeq(s.ID.Dev) || membersN > s.v.ms.Count {
		return errors.New("keygate: MarkPushed beyond local state")
	}
	return s.bump(ch, membersN, map[string]uint64{s.ID.Dev: ownSeq})
}

// WriteCheckpoint builds, signs and stores this device's checkpoint; it returns the JSON body to push.
func (s *Store) WriteCheckpoint(now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := &checkpoint.Checkpoint{V: 1, Vault: s.cfg.Vault, Dev: s.ID.Dev, Time: now.UTC().Format(time.RFC3339),
		MembersN: s.v.ms.Count, Seen: map[string]uint64{}}
	for d, l := range s.v.logs {
		if len(l.recs) > 0 {
			cp.Seen[d] = uint64(len(l.recs))
		}
	}
	cp.Sign(s.ID.EdPriv)
	b, err := cp.Marshal()
	if err != nil {
		return nil, err
	}
	return b, fsx.WriteAtomic(cpPath(s.Home, s.ID.Dev), b)
}
