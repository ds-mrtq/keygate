package broker

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"keygate/internal/approve"
	"keygate/internal/policy"
)

// trayPeer names the tray in audit entries and prompts.
const trayPeer = "khay hệ thống"

// SecretRow is one line of the tray's Secret window: metadata only, display-ready, never a value.
type SecretRow struct {
	Key      string   `json:"key"`    // the stored name, exact: what reveal/delete act on
	Name     string   `json:"name"`   // Key sanitized for display
	Unsafe   bool     `json:"unsafe"` // Name differs from Key or collides: reveal/delete stay off
	Group    string   `json:"group"`  // first path segment ("mantis"), "(không nhóm)" without '/'
	Env      string   `json:"env"`
	Kind     string   `json:"kind"`
	Prod     bool     `json:"prod"`
	Conflict bool     `json:"conflict"`
	Grant    string   `json:"grant"`    // policy grant pattern, "" = none
	Approval string   `json:"approval"` // of that grant
	Commands []string `json:"commands"` // allow_commands, full
	Short    string   `json:"short"`    // allow_commands, shortened for the table
	Approved []string `json:"approved"` // live approved grants, one line each
	LastUsed string   `json:"last_used"`
	Recent   bool     `json:"recent"` // used within 7 days
	Writer   string   `json:"writer"` // device of the latest record
}

// SecretsForUI lists the vault's secrets for the tray (unlocks first when needed: Hello).
func (b *Broker) SecretsForUI(ctx context.Context) ([]SecretRow, error) {
	s, err := b.session(ctx)
	if err != nil {
		return nil, err
	}
	var pol *policy.Policy
	if pv, err := b.loadPolicy(s); err == nil {
		pol = pv.L.Policy
	}
	used := b.lastUsed(s)
	now := b.cfg.Now()
	approved := map[string][]string{}
	b.mu.Lock()
	for _, g := range b.grants {
		if !g.live(now) {
			continue
		}
		line := shortCmd(g.Pattern) + " · duyệt bởi " + g.By + " lúc " + g.At.Local().Format("02/01 15:04")
		if g.Durable {
			line += " · bền"
		}
		approved[g.Secret] = append(approved[g.Secret], line)
	}
	b.mu.Unlock()
	var out []SecretRow
	for _, it := range s.st.List() {
		if it.Deleted || it.Name == "" {
			continue
		}
		r := SecretRow{Name: it.Name, Env: it.Env, Kind: it.Kind, Prod: policy.IsProd(it.Name, it.Env), Conflict: it.Conflict,
			Group: "(không nhóm)", Approved: approved[it.Name]}
		if i := strings.Index(it.Name, "/"); i > 0 {
			r.Group = it.Name[:i]
		}
		if pol != nil {
			if g, err := pol.Lookup(it.Name, it.Env); err == nil && g != nil {
				r.Grant, r.Approval, r.Commands, r.Short = g.Pattern, policy.ApprovalText(g.Approval), g.AllowCommands, shortCmds(g.AllowCommands)
			}
		}
		if t, ok := used[it.Name]; ok {
			r.LastUsed = t.Local().Format("02/01/2006 15:04")
			r.Recent = now.Sub(t) < 7*24*time.Hour
		}
		switch {
		case len(it.Heads) == 1:
			h := it.Heads[0]
			r.Writer = fmt.Sprintf("%s (%s, seq %d)", h.Dev, h.Op, h.Seq)
		case len(it.Heads) > 1:
			r.Writer = fmt.Sprintf("%d bản ghi song song (xung đột)", len(it.Heads))
		}
		r.Key, r.Name = it.Name, approve.Sanitize(it.Name, 200)
		r.Unsafe = r.Name != r.Key
		out = append(out, r)
	}
	seen := map[string]int{}
	for _, r := range out {
		seen[r.Name]++
	}
	for i := range out {
		if seen[out[i].Name] > 1 {
			out[i].Unsafe = true
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// RevealFromUI shows one value in the broker's own dialog after Windows Hello (never cached by a
// work session or a grant).
func (b *Broker) RevealFromUI(ctx context.Context, name string) error {
	s, err := b.session(ctx)
	if err != nil {
		return err
	}
	return b.reveal(ctx, s, name, trayPeer)
}

// DeleteFromUI tombstones the named secrets after one Windows Hello approval at this machine (never
// offered to the phone).
func (b *Broker) DeleteFromUI(ctx context.Context, names []string) ([]string, error) {
	s, err := b.session(ctx)
	if err != nil {
		return nil, err
	}
	return b.deleteSecrets(ctx, s, names, trayPeer, true)
}
