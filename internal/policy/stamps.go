package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// GrantStamp records when a grant got its current content through `kg policy apply`. It is display
// data for the Policy window (sort by time), not a security control: nothing trusts it.
type GrantStamp struct {
	Key string    `json:"key"` // GrantFingerprint of the content it dates
	Ver uint64    `json:"ver"` // policy version that applied it
	At  time.Time `json:"at"`
}

// GrantFingerprint identifies a grant's content (commands, delivery, approval, ttl…).
func GrantFingerprint(g Grant) string {
	s := sha256.Sum256([]byte(grantKey(g)))
	return hex.EncodeToString(s[:])
}

// grantKey is the text behind GrantFingerprint, frozen as it was first written so the
// fingerprints already stored in policy.times.json keep matching. It is lossy (list boundaries,
// kind "" shown as env): only sameGrant decides whether a grant changed.
func grantKey(g Grant) string {
	fs := grantFields(g)
	if g.Kind == "" {
		fs[0].value = deliveryText(Grant{Kind: "env", EnvName: g.EnvName, TNSAlias: g.TNSAlias})
	}
	return fmt.Sprint(fs, g.AllowCommands)
}

// ReadStamps loads the stamp file; a missing or unreadable file is an empty map.
func ReadStamps(path string) map[string]GrantStamp {
	m := map[string]GrantStamp{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// UpdateStamps returns the stamps after applying cur as version ver at now: a grant whose content
// is new or changed against base gets (ver, now); a stamp still matching its grant is kept; an
// unchanged grant without a stamp stays undated (it predates stamping); removed grants drop out.
func UpdateStamps(old map[string]GrantStamp, base, cur *Policy, ver uint64, now time.Time) map[string]GrantStamp {
	baseG := map[string]Grant{}
	if base != nil {
		for _, g := range base.Grants {
			baseG[g.Pattern] = g
		}
	}
	out := map[string]GrantStamp{}
	for _, g := range cur.Grants {
		fp := GrantFingerprint(g)
		b, had := baseG[g.Pattern]
		changed := had && !sameGrant(b, g)
		if s, ok := old[g.Pattern]; ok && s.Key == fp && !changed {
			out[g.Pattern] = s
			continue
		}
		if had && !changed {
			continue
		}
		out[g.Pattern] = GrantStamp{Key: fp, Ver: ver, At: now.UTC()}
	}
	return out
}
