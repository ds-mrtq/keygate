package store

import (
	"errors"
	"fmt"
	"sort"

	"keygate/internal/fsx"
	"keygate/internal/kcrypto"
	"keygate/internal/members"
	"keygate/internal/record"
)

// Head describes one head record of an item (no secret material).
type Head struct {
	Hash  string
	Dev   string
	Seq   uint64
	Op    string
	Epoch uint64
}

// ItemInfo is a secret-free listing row.
type ItemInfo struct {
	Item          string
	Name          string // "" when no head could be decrypted
	Kind, Env     string
	Deleted       bool
	Conflict      bool
	Undecryptable bool
	Heads         []Head
}

// vaultKey returns the vault key of epoch, unwrapping with this device's key.
// Caller holds s.mu.
func (s *Store) vaultKey(epoch uint64) ([]byte, error) {
	if k, ok := s.keys[epoch]; ok {
		return k, nil
	}
	k, err := s.v.ms.UnwrapKey(epoch, s.ID.Dev, s.ID.XPriv)
	if err != nil {
		if errors.Is(err, members.ErrNoWrap) {
			return nil, fmt.Errorf("%w (epoch %d)", ErrNoKey, epoch)
		}
		return nil, err
	}
	s.keys[epoch] = k
	return k, nil
}

func (s *Store) decrypt(r *record.Record) (record.Plain, error) {
	k, err := s.vaultKey(r.Epoch)
	if err != nil {
		return record.Plain{}, err
	}
	return r.Decrypt(k)
}

func toHeads(ns []node) []Head {
	out := make([]Head, len(ns))
	for i, n := range ns {
		out[i] = Head{Hash: n.hash, Dev: n.rec.Dev, Seq: n.rec.Seq, Op: n.rec.Op, Epoch: n.rec.Epoch}
	}
	return out
}

func (s *Store) info(item string, ns []node) ItemInfo {
	it := ItemInfo{Item: item, Heads: toHeads(ns), Conflict: len(ns) > 1}
	for _, n := range ns {
		p, err := s.decrypt(n.rec)
		if err != nil {
			it.Undecryptable = true
			continue
		}
		if it.Name == "" {
			it.Name, it.Kind, it.Env = p.Name, p.Kind, p.Env
		}
		if len(ns) == 1 && n.rec.Op == record.OpTombstone {
			it.Deleted = true
		}
	}
	return it
}

// List returns all items (including deleted and conflicted) sorted by name then id.
func (s *Store) List() []ItemInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ItemInfo
	for item, ns := range s.v.itemHeads() {
		out = append(out, s.info(item, ns))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Item < out[j].Item
	})
	return out
}

// Conflicts lists items with two or more heads.
func (s *Store) Conflicts() []ItemInfo {
	var out []ItemInfo
	for _, it := range s.List() {
		if it.Conflict {
			out = append(out, it)
		}
	}
	return out
}

// FindByName returns the live (not deleted) item with the given name.
func (s *Store) FindByName(name string) (ItemInfo, error) {
	var found []ItemInfo
	for _, it := range s.List() {
		if it.Name == name && !it.Deleted {
			found = append(found, it)
		}
	}
	switch len(found) {
	case 0:
		return ItemInfo{}, ErrNotFound
	case 1:
		return found[0], nil
	}
	return ItemInfo{}, fmt.Errorf("keygate: %d items share this name", len(found))
}

// Get decrypts the single head of item. ErrConflict for several heads, ErrDeleted for a tombstone
// (the plaintext then carries only the name), ErrNotFound if unknown.
func (s *Store) Get(item string) (record.Plain, *record.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns := s.v.itemHeads()[item]
	switch {
	case len(ns) == 0:
		return record.Plain{}, nil, ErrNotFound
	case len(ns) > 1:
		return record.Plain{}, nil, ErrConflict
	}
	p, err := s.decrypt(ns[0].rec)
	if err != nil {
		return record.Plain{}, nil, err
	}
	if ns[0].rec.Op == record.OpTombstone {
		return p, ns[0].rec, ErrDeleted
	}
	return p, ns[0].rec, nil
}

// Put writes a new version of item ("" creates a new item). Returns the record.
func (s *Store) Put(item string, p record.Plain) (*record.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var parent *string
	if item == "" {
		item = kcrypto.NewItemID()
	} else {
		ns := s.v.itemHeads()[item]
		if len(ns) > 1 {
			return nil, ErrConflict
		}
		if len(ns) == 1 {
			parent = record.StrPtr(ns[0].hash)
		}
	}
	return s.appendRecord(item, parent, nil, record.OpPut, p)
}

// Delete writes a tombstone for item.
func (s *Store) Delete(item string) (*record.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns := s.v.itemHeads()[item]
	if len(ns) == 0 {
		return nil, ErrNotFound
	}
	if len(ns) > 1 {
		return nil, ErrConflict
	}
	p, err := s.decrypt(ns[0].rec)
	if err != nil {
		return nil, err
	}
	return s.appendRecord(item, record.StrPtr(ns[0].hash), nil, record.OpTombstone, record.Plain{Name: p.Name})
}

// ResolveConflict writes a merge record keeping the head identified by keep (a record hash, or a
// device id that owns exactly one head); the other heads go into merge.
func (s *Store) ResolveConflict(item, keep string) (*record.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns := s.v.itemHeads()[item]
	if len(ns) < 2 {
		return nil, errors.New("keygate: item is not in conflict")
	}
	var chosen *node
	for i := range ns {
		if ns[i].hash == keep || ns[i].rec.Dev == keep {
			if chosen != nil {
				return nil, errors.New("keygate: --keep is ambiguous, use the record hash")
			}
			chosen = &ns[i]
		}
	}
	if chosen == nil {
		return nil, errors.New("keygate: --keep matches no head")
	}
	p, err := s.decrypt(chosen.rec)
	if err != nil {
		return nil, err
	}
	var merge []string
	for _, n := range ns {
		if n.hash != chosen.hash {
			merge = append(merge, n.hash)
		}
	}
	return s.appendRecord(item, record.StrPtr(chosen.hash), merge, chosen.rec.Op, p)
}

// ReencryptLive rewrites every live single-head item with the current epoch (after an epoch bump).
// Items in conflict or without a decryptable head are skipped. Returns the number rewritten.
func (s *Store) ReencryptLive() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reencryptLocked()
}

func (s *Store) reencryptLocked() (int, error) {
	n := 0
	heads := s.v.itemHeads()
	items := make([]string, 0, len(heads))
	for it := range heads {
		items = append(items, it)
	}
	sort.Strings(items)
	for _, item := range items {
		ns := heads[item]
		if len(ns) != 1 || ns[0].rec.Op != record.OpPut || ns[0].rec.Epoch >= s.v.ms.Epoch {
			continue
		}
		p, err := s.decrypt(ns[0].rec)
		if err != nil {
			continue
		}
		if _, err := s.appendRecord(item, record.StrPtr(ns[0].hash), nil, record.OpPut, p); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// appendRecord builds, signs, verifies and appends a record to this device's log. Caller holds s.mu.
func (s *Store) appendRecord(item string, parent *string, merge []string, op string, p record.Plain) (*record.Record, error) {
	me, ok := s.v.ms.Devices[s.ID.Dev]
	if !ok || me.Revoked {
		return nil, ErrNotMember
	}
	vk, err := s.vaultKey(s.v.ms.Epoch)
	if err != nil {
		return nil, err
	}
	dl := s.v.logs[s.ID.Dev]
	if dl == nil {
		dl = &devLog{}
		s.v.logs[s.ID.Dev] = dl
	}
	r := &record.Record{V: record.CurrentVer, Vault: s.cfg.Vault, Item: item, Parent: parent, Merge: merge,
		Dev: s.ID.Dev, Seq: uint64(len(dl.recs)) + 1, Epoch: s.v.ms.Epoch, Op: op}
	if n := len(dl.hashes); n > 0 {
		r.Prev = record.StrPtr(dl.hashes[n-1])
	}
	if err := r.Encrypt(vk, p); err != nil {
		return nil, err
	}
	if err := r.Sign(s.ID.EdPriv); err != nil {
		return nil, err
	}
	line, err := r.Marshal()
	if err != nil {
		return nil, err
	}
	// Defence in depth: the line must parse and verify exactly like any ingested line.
	if rr, err := record.Parse(line); err != nil || rr.Verify(s.ID.EdPub) != nil {
		return nil, errors.New("keygate: internal error: produced record does not verify")
	}
	h, _ := r.Hash()
	if err := fsx.AppendLines(logPath(s.Home, s.ID.Dev), line); err != nil {
		return nil, err
	}
	dl.recs = append(dl.recs, r)
	dl.hashes = append(dl.hashes, h)
	dl.lines = append(dl.lines, line)
	s.v.byHash[h] = r
	return r, nil
}
