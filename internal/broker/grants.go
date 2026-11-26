package broker

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"keygate/internal/api"
	"keygate/internal/audit"
	"keygate/internal/broker/wire"
	"keygate/internal/fsx"
	"keygate/internal/kcrypto"
	"keygate/internal/policy"
)

// grantEntry is one remembered grant. Durable grants follow an explicit human approval of exactly
// that request (Hello, pasted device signature, phone decision): they survive lock, restart and the
// end of a work session until revoked. Session grants and `approval: none` grants are volatile.
type grantEntry struct {
	api.GrantInfo           // Secret, Pattern, Approval, Expires (zero = never expires)
	Path          string    // resolved program path (third part of grantKey)
	Dir           string    // canonical run directory (fourth part of grantKey)
	By            string    // "hello" | "paste:<dev>" | "remote:<dev>" | "session" | "none"
	At            time.Time // when it was granted
	Durable       bool
}

// live reports whether the grant has not expired.
func (g grantEntry) live(now time.Time) bool { return g.Expires.IsZero() || g.Expires.After(now) }

func (g grantEntry) view() wire.GrantView {
	v := wire.GrantView{Secret: g.Secret, Pattern: g.Pattern, Path: g.Path, Dir: g.Dir, Approval: g.Approval, By: g.By, At: g.At, Durable: g.Durable}
	if !g.Expires.IsZero() {
		e := g.Expires
		v.Expires = &e
	}
	return v
}

// dropVolatileGrants forgets every non-durable grant. The caller holds b.mu.
func (b *Broker) dropVolatileGrants() {
	for k, g := range b.grants {
		if !g.Durable {
			delete(b.grants, k)
		}
	}
}

func grantsPath(home string) string { return filepath.Join(home, "state", "grants.json") }

type grantRec struct {
	Secret   string     `json:"secret"`
	Pattern  string     `json:"pattern"`
	Path     string     `json:"path"`
	Dir      string     `json:"dir,omitempty"`
	Approval string     `json:"approval"`
	By       string     `json:"by"`
	At       time.Time  `json:"at"`
	Expires  *time.Time `json:"expires"`
}

type grantFile struct {
	V      int        `json:"v"`
	Grants []grantRec `json:"grants"`
	MAC    string     `json:"mac"`
}

func unixOrZero(t *time.Time) uint64 {
	if t == nil || t.IsZero() {
		return 0
	}
	return uint64(t.Unix())
}

// grantsMAC covers the sorted grant list, bound to this vault and device.
func grantsMAC(key []byte, vault, dev string, recs []grantRec) []byte {
	e := kcrypto.NewEnc(kcrypto.LabelLocalMac).LPS("grants").LPS(vault).LPS(dev)
	for _, r := range recs {
		e.LPS(r.Secret).LPS(r.Pattern).LPS(r.Path)
		if r.Dir != "" { // records without dir (older files) keep their original MAC input
			e.LPS(r.Dir)
		}
		e.LPS(r.Approval).LPS(r.By).U64(uint64(r.At.Unix())).U64(unixOrZero(r.Expires))
	}
	return kcrypto.MAC(key, e.Bytes())
}

func sortRecs(recs []grantRec) {
	sort.Slice(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
		if a.Secret != b.Secret {
			return a.Secret < b.Secret
		}
		if a.Pattern != b.Pattern {
			return a.Pattern < b.Pattern
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Dir < b.Dir
	})
}

// persistGrants writes the durable grants to KG_HOME/state/grants.json (MAC'd with the device local
// key). Call without b.mu held.
func (b *Broker) persistGrants() {
	b.mu.Lock()
	id, vault := b.id, b.vaultID
	var recs []grantRec
	for _, g := range b.grants {
		if !g.Durable {
			continue
		}
		r := grantRec{Secret: g.Secret, Pattern: g.Pattern, Path: g.Path, Dir: g.Dir, Approval: g.Approval, By: g.By, At: g.At.UTC().Truncate(time.Second)}
		if !g.Expires.IsZero() {
			e := g.Expires.UTC().Truncate(time.Second)
			r.Expires = &e
		}
		recs = append(recs, r)
	}
	b.mu.Unlock()
	if id == nil || vault == "" {
		return
	}
	sortRecs(recs)
	f := grantFile{V: 1, Grants: recs}
	if f.Grants == nil {
		f.Grants = []grantRec{}
	}
	f.MAC = base64.StdEncoding.EncodeToString(grantsMAC(id.LocalMacKey(), vault, id.Dev, recs))
	data, err := json.Marshal(f)
	if err == nil {
		b.grantsFileMu.Lock()
		defer b.grantsFileMu.Unlock()
		if err = os.MkdirAll(filepath.Dir(grantsPath(b.cfg.Home)), 0o700); err == nil {
			err = fsx.WriteAtomic(grantsPath(b.cfg.Home), data)
		}
	}
	if err != nil {
		b.logf("không ghi được grants.json: %v", err)
	}
}

// loadGrants reads grants.json: missing = none; broken JSON or a wrong MAC drops everything.
func (b *Broker) loadGrants() {
	data, err := os.ReadFile(grantsPath(b.cfg.Home))
	if err != nil {
		return
	}
	bad := func() { b.logf("grants.json không hợp lệ, bỏ qua") }
	var f grantFile
	if json.Unmarshal(data, &f) != nil || f.V != 1 {
		bad()
		return
	}
	mac, err := base64.StdEncoding.DecodeString(f.MAC)
	if err != nil {
		bad()
		return
	}
	recs := append([]grantRec(nil), f.Grants...)
	sortRecs(recs)
	for i := range recs {
		recs[i].At = recs[i].At.UTC()
	}
	if !hmac.Equal(mac, grantsMAC(b.id.LocalMacKey(), b.vaultID, b.id.Dev, recs)) {
		bad()
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range recs {
		if r.Dir == "" {
			continue // granted before grants were bound to a directory: never matches, ask again
		}
		g := grantEntry{GrantInfo: api.GrantInfo{Secret: r.Secret, Pattern: r.Pattern, Approval: r.Approval}, Path: r.Path, Dir: r.Dir, By: r.By, At: r.At, Durable: true}
		if r.Expires != nil {
			g.Expires = *r.Expires
		}
		b.grants[grantKey{r.Secret, r.Pattern, r.Path, r.Dir}] = g
	}
}

// grantViews lists the live grants sorted by (secret, pattern, path).
func (b *Broker) grantViews() []wire.GrantView {
	now := b.cfg.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []wire.GrantView{}
	for _, g := range b.grants {
		if g.live(now) {
			out = append(out, g.view())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, c := out[i], out[j]
		if a.Secret != c.Secret {
			return a.Secret < c.Secret
		}
		if a.Pattern != c.Pattern {
			return a.Pattern < c.Pattern
		}
		if a.Path != c.Path {
			return a.Path < c.Path
		}
		return a.Dir < c.Dir
	})
	return out
}

// revokeGrants removes the grants of secret (or all) and audits it when the vault is open. Revoking
// only reduces authority, so it needs neither unlock nor approval.
func (b *Broker) revokeGrants(a wire.GrantsRevokeArgs, peer string) (int, error) {
	if !a.All && a.Secret == "" {
		return 0, fail(wire.CodeBadRequest, "cần tên secret hoặc all")
	}
	return b.revokeWhere(func(g grantEntry) bool { return a.All || g.Secret == a.Secret }, peer), nil
}

// revokeWhere removes every grant match accepts, persists, and audits (vault open) or logs (locked).
func (b *Broker) revokeWhere(match func(grantEntry) bool, peer string) int {
	b.mu.Lock()
	s := b.sess
	var gone []grantEntry
	for k, g := range b.grants {
		if match(g) {
			gone = append(gone, g)
			delete(b.grants, k)
		}
	}
	b.mu.Unlock()
	if len(gone) == 0 {
		return 0
	}
	b.persistGrants()
	for _, g := range gone {
		if s != nil {
			b.audBest(s, audit.Entry{Event: audit.EvGrantRevoke, Secret: g.Secret, Argv: []string{g.Pattern}, Approval: g.By, Peer: peer})
		} else {
			b.logf("đã thu hồi grant %s | %s (vault đang khóa, không ghi audit)", g.Secret, g.Pattern)
		}
	}
	b.changed()
	return len(gone)
}

// dropGrantsOnApply removes the durable grants a new policy no longer backs as approved: the
// allow_commands entry is gone, or the grant that governs the secret (Lookup) is now another one
// (an exact grant removed so the secret falls back to a wildcard, overlapping wildcards reordered).
// The latter matters even when the new grant lists the same command: it may differ in ttl, delivery
// or scope, and the approval was given for the old grant. old is the last applied policy (nil =
// none verified); env maps vault secret names to their env.
func (b *Broker) dropGrantsOnApply(old, cur *policy.Policy, env map[string]string) int {
	keep := map[string]bool{}
	for _, g := range cur.Grants {
		for _, c := range g.AllowCommands {
			keep[c] = true
		}
	}
	b.mu.Lock()
	n := 0
	for k, g := range b.grants {
		if !g.Durable {
			continue
		}
		if !keep[g.Pattern] || governing(old, g.Secret, env[g.Secret]) != governing(cur, g.Secret, env[g.Secret]) {
			delete(b.grants, k)
			n++
		}
	}
	b.mu.Unlock()
	if n > 0 {
		b.persistGrants()
	}
	return n
}

// governing is the pattern of the grant that decides name under p ("" = none, or denied).
func governing(p *policy.Policy, name, env string) string {
	if p == nil {
		return ""
	}
	g, err := p.Lookup(name, env)
	if err != nil || g == nil {
		return ""
	}
	return g.Pattern
}
