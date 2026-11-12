package store

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"

	"keygate/internal/checkpoint"
	"keygate/internal/members"
	"keygate/internal/record"
)

// devLog is a verified, contiguous per-device log.
type devLog struct {
	recs   []*record.Record
	hashes []string
	lines  [][]byte
}

// view is the verified in-memory state: member chain + all device logs.
type view struct {
	vault  string
	ms     *members.State
	mhash  []string
	mlines [][]byte
	logs   map[string]*devLog
	byHash map[string]*record.Record
	pin    string // when set, genesis hash must equal it
}

func newView(vault string) *view {
	return &view{vault: vault, ms: members.NewState(), logs: map[string]*devLog{}, byHash: map[string]*record.Record{}}
}

func (v *view) clone() *view {
	c := *v
	c.ms = v.ms.Clone()
	c.mhash = slices.Clone(v.mhash)
	c.mlines = slices.Clone(v.mlines)
	c.byHash = maps.Clone(v.byHash)
	c.logs = make(map[string]*devLog, len(v.logs))
	for d, l := range v.logs {
		c.logs[d] = &devLog{recs: slices.Clone(l.recs), hashes: slices.Clone(l.hashes), lines: slices.Clone(l.lines)}
	}
	return &c
}

func (v *view) lastSeq(dev string) uint64 {
	if l := v.logs[dev]; l != nil {
		return uint64(len(l.recs))
	}
	return 0
}

func wrapErr(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", kind, fmt.Sprintf(format, args...))
}

// verifyMembers applies incoming member lines (already-held events must match byte-for-byte hash).
// It returns the lines that were new and the number of events the channel proved to hold.
func verifyMembers(v *view, incoming [][]byte) (fresh [][]byte, seen uint64, err error) {
	for _, l := range incoming {
		ev, perr := members.Parse(l)
		if perr != nil {
			return nil, 0, wrapErr(ErrBrokenChain, "members: %v", perr)
		}
		if v.vault != "" && ev.Vault != v.vault {
			return nil, 0, wrapErr(ErrBrokenChain, "members: foreign vault")
		}
		h, herr := ev.Hash()
		if herr != nil {
			return nil, 0, wrapErr(ErrBrokenChain, "members: %v", herr)
		}
		if ev.N < v.ms.Count {
			if h != v.mhash[ev.N] {
				signer := v.ms.OwnerPub
				if ev.Type == members.TypeRevokeApprover { // signed by a device; its key never changes
					var b members.RevokeApproverBody
					if ev.DecodeBody(&b) == nil && v.ms.Devices[b.By] != nil {
						signer = v.ms.Devices[b.By].EdPub
					}
				}
				if serr := ev.Verify(signer); serr != nil {
					return nil, 0, wrapErr(ErrUnknownDevice, "members event %d: %v", ev.N, serr)
				}
				return nil, 0, wrapErr(ErrBrokenChain, "members event %d differs from local (owner fork)", ev.N)
			}
		} else {
			if aerr := v.ms.Apply(ev); aerr != nil {
				if errors.Is(aerr, members.ErrBadOwnerSig) {
					return nil, 0, wrapErr(ErrUnknownDevice, "members event %d: %v", ev.N, aerr)
				}
				return nil, 0, wrapErr(ErrBrokenChain, "members event %d: %v", ev.N, aerr)
			}
			if ev.N == 0 && v.pin != "" && h != v.pin {
				return nil, 0, wrapErr(ErrBrokenChain, "genesis differs from pinned vault")
			}
			if ev.N == 0 {
				v.vault = ev.Vault
			}
			v.mhash = append(v.mhash, h)
			cp := slices.Clone(l)
			v.mlines = append(v.mlines, cp)
			fresh = append(fresh, cp)
		}
		if ev.N+1 > seen {
			seen = ev.N + 1
		}
	}
	return fresh, seen, nil
}

// verifyLogs verifies incoming per-device lines against v and appends the new ones.
// maxSeq reports the highest valid seq the channel presented per device.
func verifyLogs(v *view, logs map[string][][]byte) (fresh map[string][][]byte, maxSeq map[string]uint64, err error) {
	fresh = map[string][][]byte{}
	maxSeq = map[string]uint64{}
	devs := make([]string, 0, len(logs))
	for d := range logs {
		devs = append(devs, d)
	}
	sort.Strings(devs)
	for _, dev := range devs {
		for _, l := range logs[dev] {
			rec, perr := record.Parse(l)
			if perr != nil {
				return nil, nil, wrapErr(ErrBadSignature, "log %s: %v", dev, perr)
			}
			if rec.Vault != v.vault {
				return nil, nil, wrapErr(ErrUnknownDevice, "log %s: foreign vault", dev)
			}
			if rec.Dev != dev {
				return nil, nil, wrapErr(ErrBrokenChain, "log %s holds a record of %s", dev, rec.Dev)
			}
			d, ok := v.ms.Devices[rec.Dev]
			if !ok {
				return nil, nil, wrapErr(ErrUnknownDevice, "%s is not a member", rec.Dev)
			}
			if d.Role == members.RoleApprover {
				return nil, nil, wrapErr(ErrUnknownDevice, "%s is an approver and cannot write records", rec.Dev)
			}
			if d.Revoked && rec.Seq > d.LastSeq {
				continue // beyond the owner-pinned last_seq: dropped, never stored
			}
			if serr := rec.Verify(d.EdPub); serr != nil {
				return nil, nil, wrapErr(ErrBadSignature, "%s seq %d", dev, rec.Seq)
			}
			h, _ := rec.Hash()
			if d.Revoked && rec.Seq == d.LastSeq && d.LastHash != h {
				return nil, nil, wrapErr(ErrBrokenChain, "%s seq %d does not match the revoked last_hash", dev, rec.Seq)
			}
			dl := v.logs[dev]
			if dl == nil {
				dl = &devLog{}
				v.logs[dev] = dl
			}
			last := uint64(len(dl.recs))
			switch {
			case rec.Seq <= last:
				if dl.hashes[rec.Seq-1] != h {
					return nil, nil, wrapErr(ErrBrokenChain, "%s seq %d differs from local copy (fork)", dev, rec.Seq)
				}
			case rec.Seq == last+1:
				if (last == 0) != (rec.Prev == nil) || (last > 0 && *rec.Prev != dl.hashes[last-1]) {
					return nil, nil, wrapErr(ErrBrokenChain, "%s seq %d prev hash mismatch", dev, rec.Seq)
				}
				for _, ref := range append([]string{derefOr(rec.Parent)}, rec.Merge...) {
					if t, ok := v.byHash[ref]; ok && t.Item != rec.Item {
						return nil, nil, fmt.Errorf("%w: %s seq %d references another item", record.ErrMalformed, dev, rec.Seq)
					}
				}
				cp := slices.Clone(l)
				dl.recs = append(dl.recs, rec)
				dl.hashes = append(dl.hashes, h)
				dl.lines = append(dl.lines, cp)
				v.byHash[h] = rec
				fresh[dev] = append(fresh[dev], cp)
			default:
				return nil, nil, wrapErr(ErrBrokenChain, "%s seq jumps from %d to %d", dev, last, rec.Seq)
			}
			if rec.Seq > maxSeq[dev] {
				maxSeq[dev] = rec.Seq
			}
		}
	}
	return fresh, maxSeq, nil
}

// verifyCheckpoints validates checkpoints against the already-staged view and detects withheld records.
// It returns the raw bodies of valid checkpoints per device.
func verifyCheckpoints(v *view, cps map[string][]byte) (map[string]*checkpoint.Checkpoint, error) {
	out := map[string]*checkpoint.Checkpoint{}
	devs := make([]string, 0, len(cps))
	for d := range cps {
		devs = append(devs, d)
	}
	sort.Strings(devs)
	for _, dev := range devs {
		cp, err := checkpoint.Parse(cps[dev])
		if err != nil {
			return nil, wrapErr(ErrBadSignature, "checkpoint %s: %v", dev, err)
		}
		if cp.Dev != dev || cp.Vault != v.vault {
			return nil, wrapErr(ErrBadSignature, "checkpoint %s: wrong owner/vault", dev)
		}
		d, ok := v.ms.Devices[cp.Dev]
		if !ok {
			return nil, wrapErr(ErrUnknownDevice, "checkpoint from non-member %s", dev)
		}
		if d.Revoked {
			continue // a revoked device's checkpoints carry no weight
		}
		if d.Role == members.RoleApprover {
			continue // approvers never write checkpoints
		}
		if err := cp.Verify(d.EdPub); err != nil {
			return nil, wrapErr(ErrBadSignature, "checkpoint %s", dev)
		}
		if cp.MembersN > v.ms.Count {
			return nil, wrapErr(ErrHidden, "checkpoint of %s saw %d member events, channel gave %d", dev, cp.MembersN, v.ms.Count)
		}
		for x, s := range cp.Seen {
			if dx, ok := v.ms.Devices[x]; ok && dx.Revoked && s > dx.LastSeq {
				s = dx.LastSeq
			}
			if _, ok := v.ms.Devices[x]; ok && s > v.lastSeq(x) {
				return nil, wrapErr(ErrHidden, "checkpoint of %s saw %s seq %d, channel gave %d", dev, x, s, v.lastSeq(x))
			}
		}
		out[dev] = cp
	}
	return out, nil
}

// ---- items graph ----

type node struct {
	rec  *record.Record
	hash string
}

// itemHeads returns, per item, the records no other record points to (sorted by dev, seq).
func (v *view) itemHeads() map[string][]node {
	referenced := map[string]bool{}
	byItem := map[string][]node{}
	for _, l := range v.logs {
		for i, r := range l.recs {
			byItem[r.Item] = append(byItem[r.Item], node{r, l.hashes[i]})
			for _, ref := range append([]string{derefOr(r.Parent)}, r.Merge...) {
				if t, ok := v.byHash[ref]; ok && t.Item == r.Item {
					referenced[ref] = true
				}
			}
		}
	}
	heads := map[string][]node{}
	for item, ns := range byItem {
		for _, n := range ns {
			if !referenced[n.hash] {
				heads[item] = append(heads[item], n)
			}
		}
		h := heads[item]
		sort.Slice(h, func(i, j int) bool {
			if h[i].rec.Dev != h[j].rec.Dev {
				return h[i].rec.Dev < h[j].rec.Dev
			}
			return h[i].rec.Seq < h[j].rec.Seq
		})
	}
	return heads
}

func derefOr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// clampRevoked drops records above last_seq of revoked devices from the view and checks that the
// kept record at last_seq has the owner-pinned hash.
func clampRevoked(v *view) error {
	for id, d := range v.ms.Devices {
		if !d.Revoked {
			continue
		}
		dl := v.logs[id]
		if dl == nil {
			continue
		}
		for uint64(len(dl.recs)) > d.LastSeq {
			n := len(dl.recs) - 1
			delete(v.byHash, dl.hashes[n])
			dl.recs, dl.hashes, dl.lines = dl.recs[:n], dl.hashes[:n], dl.lines[:n]
		}
		if d.LastSeq > 0 && uint64(len(dl.recs)) == d.LastSeq && dl.hashes[d.LastSeq-1] != d.LastHash {
			return wrapErr(ErrBrokenChain, "%s seq %d does not match the revoked last_hash", id, d.LastSeq)
		}
	}
	return nil
}
