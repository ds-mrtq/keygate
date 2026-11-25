package broker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"keygate/internal/approve"
	"keygate/internal/policy"
)

// PolicyForUI describes the policy for the tray's read-only Policy window: the version in force
// (verified against the MAC'd pin) with its grants and every warning, and what policy.yaml would
// change if `kg policy apply` ran now. Unlocks first when needed (Hello), like SecretsForUI.
func (b *Broker) PolicyForUI(ctx context.Context) (approve.ReviewDoc, error) {
	s, err := b.session(ctx)
	if err != nil {
		return approve.ReviewDoc{}, err
	}
	polPath := filepath.Join(b.cfg.Home, "policy.yaml")
	pinPath := filepath.Join(b.cfg.Home, "state", "policy.pin")
	keptPath := filepath.Join(b.cfg.Home, "state", "policy.pinned.yaml")
	cur, curErr := os.ReadFile(polPath)
	var applied *policy.Policy
	var ver uint64
	var pinHash, when string
	if h, v, err := policy.ReadPin(pinPath, s.st.LocalMacKey()); err == nil {
		pinHash, ver = h, v
		for _, src := range [][]byte{readOrNil(keptPath), cur} { // pins made before policy.pinned.yaml existed
			if src != nil && policy.Hash(src) == h {
				applied, _ = policy.Parse(src)
				break
			}
		}
		if fi, err := os.Stat(pinPath); err == nil {
			when = fi.ModTime().Local().Format("02/01/2006 15:04")
		}
	}
	var curPol *policy.Policy
	var parseErr error
	if curErr == nil {
		curPol, parseErr = policy.Parse(cur)
	}
	stamps := policy.ReadStamps(filepath.Join(b.cfg.Home, "state", "policy.times.json"))
	var blocked error
	if applied != nil {
		_, blocked = b.loadPolicy(s) // same check as kg run: pin hash/MAC and the version floor
	}
	return policyOverview(polPath, applied, ver, when, stamps, curPol, curErr == nil && policy.Hash(cur) != pinHash, firstErr(curErr, parseErr), blocked), nil
}

func readOrNil(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return b
}

func firstErr(es ...error) error {
	for _, e := range es {
		if e != nil {
			return e
		}
	}
	return nil
}

// policyOverview builds the Policy window: applied = the last approved version verified by its pin
// (nil = none), stamps = when each grant got its content, cur = policy.yaml as parsed now (nil when
// unreadable: curErr), pending = cur differs from it, blocked = why kg run refuses every grant now
// (nil = applied is in force).
func policyOverview(polPath string, applied *policy.Policy, ver uint64, when string, stamps map[string]policy.GrantStamp, cur *policy.Policy, pending bool, curErr, blocked error) approve.ReviewDoc {
	doc := approve.ReviewDoc{Requester: "Policy", Chain: approve.Sanitize(polPath, 500)}
	inForce := applied != nil
	// whenOf dates a grant in force: a matching stamp, else it predates stamping (≤ this version).
	whenOf := func(g policy.Grant) string {
		if !inForce {
			return "chưa áp dụng"
		}
		if s, ok := stamps[g.Pattern]; ok && s.Key == policy.GrantFingerprint(g) {
			return fmt.Sprintf("%s (v%d)", s.At.Local().Format("02/01/2006 15:04"), s.Ver)
		}
		return fmt.Sprintf("không rõ (≤ v%d)", ver)
	}
	var t strings.Builder
	if applied == nil {
		doc.Action = "chưa có bản đã áp dụng xác minh được"
		doc.Note = "kg run chỉ dùng policy đã áp dụng (kg policy apply, cần Windows Hello). Bảng dưới là nội dung policy.yaml hiện tại."
		doc.Badges = append(doc.Badges, approve.Badge{Text: "chưa áp dụng", Tone: approve.ToneDel})
	} else if blocked != nil {
		doc.Action = fmt.Sprintf("v%d đã duyệt nhưng kg run đang bị chặn", ver)
		doc.Note = "policy.yaml (hoặc pin) không khớp bản đã duyệt nên kg run từ chối mọi secret. Chạy kg policy apply để duyệt bản mới, hoặc trả policy.yaml về bản đã duyệt. Bảng dưới là các quyền của bản đã duyệt gần nhất."
		if when != "" {
			doc.Action += " (duyệt lúc " + when + ")"
		}
		doc.Badges = append(doc.Badges, approve.Badge{Text: "kg run bị chặn", Tone: approve.ToneDel})
	} else {
		doc.Action = fmt.Sprintf("đang áp dụng v%d", ver)
		doc.Note = "Quyền kg run đang dùng và mọi cảnh báo của chúng. Cửa sổ chỉ để xem; muốn đổi thì sửa policy.yaml rồi chạy kg policy apply."
		if when != "" {
			doc.Action += " (áp dụng lúc " + when + ")"
		}
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("v%d đang áp dụng", ver), Tone: approve.ToneAdd})
	}
	fmt.Fprintf(&t, "Policy %s.\nFile: %s\n\n", doc.Action, doc.Chain)
	if blocked != nil {
		fmt.Fprintf(&t, "kg run đang bị chặn: %s\n\n", approve.Sanitize(blocked.Error(), 300))
	}
	if curErr != nil {
		msg := approve.Sanitize(curErr.Error(), 300)
		fmt.Fprintf(&t, "policy.yaml hiện tại không đọc được: %s\n\n", msg)
		doc.Badges = append(doc.Badges, approve.Badge{Text: "policy.yaml lỗi", Tone: approve.ToneDel})
	}
	switch {
	case applied == nil:
		applied = cur // nothing in force: describe policy.yaml itself below (nil when unreadable)
	case cur != nil && pending: // what `kg policy apply` would change now
		changes := policy.Changes(applied, cur)
		if len(changes) > 0 {
			fmt.Fprintf(&t, "THAY ĐỔI CHƯA ÁP DỤNG (%d):\n", len(changes))
			for _, c := range changes {
				t.WriteString(sanitizeLines(c.Text(), 2000) + "\n\n")
				r := changeRow(c)
				r.When = "chưa áp dụng"
				doc.Rows = append(doc.Rows, r)
			}
			doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d thay đổi chưa áp dụng", len(changes)), Tone: approve.ToneMod})
		}
		warns, _ := policy.Warnings(applied, cur)
		var news []policy.Warning
		for _, w := range warns {
			if !w.Old {
				news = append(news, w)
			}
		}
		if len(news) > 0 {
			fmt.Fprintf(&t, "CẢNH BÁO của thay đổi chưa áp dụng (%d):\n", len(news))
			for _, w := range news {
				t.WriteString(approve.Sanitize(w.Text(), 1000) + "\n")
				r := warnRow(w)
				r.Label, r.When = "Chưa áp dụng", "chưa áp dụng"
				doc.Rows = append(doc.Rows, r)
			}
			t.WriteString("\n")
		}
	}
	if applied == nil {
		doc.Text = t.String()
		return doc
	}
	byPat := map[string]policy.Grant{}
	for _, g := range applied.Grants {
		byPat[g.Pattern] = g
	}
	warns, _ := policy.Warnings(applied, applied) // every grant equals itself: PROD alone is no warning here
	if len(warns) > 0 {
		fmt.Fprintf(&t, "CẢNH BÁO (%d):\n", len(warns))
		for _, w := range warns {
			t.WriteString(approve.Sanitize(w.Text(), 1000) + "\n")
			r := warnRow(w)
			if g, ok := byPat[w.Secret]; ok {
				r.Approval, r.When = approve.Sanitize(policy.ApprovalText(g.Approval), 100), whenOf(g)
			}
			doc.Rows = append(doc.Rows, r)
		}
		t.WriteString("\n")
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d cảnh báo", len(warns)), Tone: approve.ToneWarn})
	} else {
		doc.Badges = append(doc.Badges, approve.Badge{Text: "không cảnh báo", Tone: approve.ToneAdd})
	}
	nProd := 0
	fmt.Fprintf(&t, "QUYỀN (%d grant):\n", len(applied.Grants))
	for _, c := range policy.Changes(nil, applied) {
		if c.Op != policy.ChangeAdd {
			continue // the oracle tool settings are not a grant
		}
		if c.Prod {
			nProd++
		}
		d := grantText(c) + "\n  áp dụng lúc: " + whenOf(byPat[c.Secret])
		t.WriteString(d + "\n\n")
		doc.Rows = append(doc.Rows, approve.ReviewRow{Group: approve.GroupGrant, Op: "grant", Label: "Quyền",
			Secret: approve.Sanitize(c.Secret, 200), Prod: c.Prod, What: approve.Sanitize(shortCmds(c.Commands), 500),
			Approval: approve.Sanitize(c.Approval, 100), TTL: approve.Sanitize(c.TTL, 50), When: whenOf(byPat[c.Secret]), Detail: d})
	}
	doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d grant", len(applied.Grants)), Tone: approve.ToneMuted})
	if nProd > 0 {
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d PROD", nProd), Tone: approve.ToneMuted})
	}
	doc.Text = t.String()
	return doc
}

// grantText is the detail of one grant in force (sanitized, multi-line).
func grantText(c policy.Change) string {
	var b strings.Builder
	b.WriteString("Secret " + c.Secret + "\n  lệnh được nhận secret:")
	if len(c.Commands) == 0 {
		b.WriteString(" (không lệnh nào)")
	}
	for _, x := range c.Commands {
		b.WriteString("\n    • " + x)
	}
	fmt.Fprintf(&b, "\n  cấp dạng: %s\n  duyệt: %s\n  hết hạn: %s", c.Delivery, c.Approval, c.TTL)
	for _, f := range c.Fields {
		fmt.Fprintf(&b, "\n  %s: %s", f.Label, f.New)
	}
	return sanitizeLines(b.String(), 2000)
}
