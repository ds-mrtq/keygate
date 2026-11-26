package broker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keygate/internal/approve"
	"keygate/internal/policy"
)

// The apply dialog lists only what this change decides; warnings of unchanged grants are counted,
// and the Policy window lists every grant and warning of the version in force.
func TestPolicyReviewOnlyNewWarnings(t *testing.T) {
	base, err := policy.Parse([]byte("grants:\n  a/*:\n    allow_commands: [curl]\n"))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := policy.Parse([]byte("grants:\n  a/*:\n    allow_commands: [curl]\n  b/*:\n    allow_commands: [curl]\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, doc, nChange, nWarn := policyReview("policy.yaml", base, cur, 3)
	if nChange != 1 || nWarn != 1 {
		t.Fatalf("changes=%d warns=%d, want 1/1", nChange, nWarn)
	}
	for _, r := range doc.Rows {
		if strings.HasPrefix(r.Secret, "a/") {
			t.Fatalf("unchanged grant listed in the apply dialog: %+v", r)
		}
	}
	if !hasBadge(doc.Badges, "1 cảnh báo cũ") || !strings.Contains(doc.Text, "1 cảnh báo cũ") {
		t.Fatalf("old warning not counted: %v\n%s", doc.Badges, doc.Text)
	}

	t1 := time.Date(2026, 11, 1, 8, 0, 0, 0, time.Local)
	st := policy.UpdateStamps(nil, nil, base, 1, t1) // v1: a/* new
	if st2 := policy.UpdateStamps(st, base, cur, 2, t1.Add(time.Hour)); st2["a/*"].Ver != 1 || st2["b/*"].Ver != 2 {
		t.Fatalf("stamps after v2: %+v", st2)
	}
	if st3 := policy.UpdateStamps(nil, base, cur, 2, t1); len(st3) != 1 || st3["b/*"].Ver != 2 {
		t.Fatalf("unchanged grant without a stamp must stay undated: %+v", st3)
	}
	ov := policyOverview("policy.yaml", base, 3, "", st, cur, true, nil, nil)
	var grants, warns, changes int
	for _, r := range ov.Rows {
		switch r.Group {
		case approve.GroupGrant:
			grants++
		case approve.GroupWarn:
			warns++
		case approve.GroupChange:
			changes++
		}
	}
	// in force: a/* (1 grant, 1 warning); pending: + b/* and its warning.
	if grants != 1 || warns != 2 || changes != 1 || !hasBadge(ov.Badges, "1 thay đổi chưa áp dụng") {
		t.Fatalf("overview grants=%d warns=%d changes=%d badges=%v", grants, warns, changes, ov.Badges)
	}
	for _, r := range ov.Rows {
		want := "01/11/2026 08:00 (v1)" // a/*, dated by its stamp
		if r.Group == approve.GroupChange || r.Label == "Chưa áp dụng" {
			want = "chưa áp dụng"
		}
		if r.When != want {
			t.Fatalf("row %s/%s when=%q, want %q", r.Group, r.Secret, r.When, want)
		}
	}
	if ov := policyOverview("policy.yaml", nil, 0, "", nil, cur, true, nil, nil); !hasBadge(ov.Badges, "chưa áp dụng") || len(ov.Rows) != 4 {
		t.Fatalf("nothing applied: badges=%v rows=%d", ov.Badges, len(ov.Rows))
	}
}

// An edited policy.yaml that was not applied blocks every kg run (pin mismatch): the Policy window
// must say so instead of calling the last approved version "in force".
func TestPolicyWindowShowsBlockedRun(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.policy(basePolicy, true)
	if err := os.WriteFile(filepath.Join(f.home, "state", "policy.pinned.yaml"), []byte(basePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	ov, err := f.b.PolicyForUI(context.Background())
	if err != nil || !hasBadge(ov.Badges, "v1 đang áp dụng") || hasBadge(ov.Badges, "kg run bị chặn") {
		t.Fatalf("pinned policy: err=%v badges=%v", err, ov.Badges)
	}
	f.policy(basePolicy+"  extra/*:\n    allow_commands: [curl]\n", false) // edited, not applied
	ov, err = f.b.PolicyForUI(context.Background())
	if err != nil || !hasBadge(ov.Badges, "kg run bị chặn") || hasBadge(ov.Badges, "v1 đang áp dụng") || !strings.Contains(ov.Action, "bị chặn") {
		t.Fatalf("edited policy: err=%v action=%q badges=%v", err, ov.Action, ov.Badges)
	}
}

// Reordering two overlapping, equally specific wildcard grants must produce change rows in both
// the `kg policy apply` approval dialog and the tray Policy window's pending preview.
func TestPolicyApplyAndWindowShowOverlappingWildcardReorder(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "team/qa/db", "qa")
	ctx := context.Background()

	polV1 := `grants:
  team/*/db:
    allow_commands: ["sql /@HTTEST"]
    approval: user-presence
  team/qa/*:
    allow_commands: ["curl"]
    approval: device
`
	polV2 := `grants:
  team/qa/*:
    allow_commands: ["curl"]
    approval: device
  team/*/db:
    allow_commands: ["sql /@HTTEST"]
    approval: user-presence
`
	f.policy(polV1, false)
	if _, err := f.cli.PolicyApply(ctx); err != nil {
		t.Fatal(err)
	}

	// Swap the two wildcards without applying yet: PolicyForUI must show pending changes.
	f.policy(polV2, false)
	ov, err := f.b.PolicyForUI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !hasBadge(ov.Badges, "2 thay đổi chưa áp dụng") {
		t.Fatalf("PolicyForUI missing pending wildcard reorder changes: badges=%v\n%s", ov.Badges, ov.Text)
	}
	if !strings.Contains(ov.Text, "ưu tiên wildcard: sau team/*/db → trước team/*/db") ||
		!strings.Contains(ov.Text, "quyền áp dụng: team/*/db → team/qa/*") {
		t.Fatalf("PolicyForUI text missing precedence/secret change:\n%s", ov.Text)
	}

	// Now run `kg policy apply`: the approval prompt must show both rows (not 0 changes).
	before := len(f.prompt.String())
	if _, err := f.cli.PolicyApply(ctx); err != nil {
		t.Fatal(err)
	}
	out := f.prompt.String()[before:]
	for _, want := range []string{
		"2 thay đổi",
		"~ SỬA quyền dùng secret team/qa/*",
		"ưu tiên wildcard: sau team/*/db → trước team/*/db",
		"~ SỬA quyền dùng secret team/qa/db",
		"quyền áp dụng: team/*/db → team/qa/*",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("kg policy apply prompt lacks %q:\n%s", want, out)
		}
	}
}

// Removing an exact-name grant while a wildcard still matches must disclose the fallback wildcard
// and its settings in both `kg policy apply` and the tray Policy window.
func TestPolicyApplyAndWindowShowExactGrantDeletionWildcardFallback(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "team/qa/db", "qa")
	ctx := context.Background()

	polV1 := `grants:
  team/qa/db:
    allow_commands: ["sql /@HTTEST"]
    approval: user-presence
  team/*:
    allow_commands: ["curl"]
    approval: device
`
	polV2 := `grants:
  team/*:
    allow_commands: ["curl"]
    approval: device
`
	f.policy(polV1, false)
	if _, err := f.cli.PolicyApply(ctx); err != nil {
		t.Fatal(err)
	}

	f.policy(polV2, false)
	ov, err := f.b.PolicyForUI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var delRow *approve.ReviewRow
	for i := range ov.Rows {
		if ov.Rows[i].Group == approve.GroupChange && ov.Rows[i].Secret == "team/qa/db" {
			delRow = &ov.Rows[i]
			break
		}
	}
	if delRow == nil {
		t.Fatalf("PolicyForUI missing pending deletion row for team/qa/db: %+v", ov.Rows)
	}
	if !strings.Contains(delRow.What, "rơi về team/*") || !strings.Contains(delRow.What, "curl") {
		t.Fatalf("PolicyForUI deletion row does not show wildcard fallback: %+v", *delRow)
	}
	if delRow.Approval != "chữ ký điện thoại" {
		t.Fatalf("PolicyForUI deletion row approval=%q, want fallback approval", delRow.Approval)
	}

	before := len(f.prompt.String())
	if _, err := f.cli.PolicyApply(ctx); err != nil {
		t.Fatal(err)
	}
	out := f.prompt.String()[before:]
	for _, want := range []string{
		"- BỎ quyền dùng secret team/qa/db (rơi về grant wildcard team/*)",
		"lệnh được nhận secret (từ team/*):",
		"curl",
		"duyệt: chữ ký điện thoại",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("kg policy apply prompt lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "lệnh sẽ phải xin duyệt lại hoặc bị chặn") {
		t.Errorf("kg policy apply prompt falsely claims secret is blocked despite wildcard fallback:\n%s", out)
	}
}

func hasBadge(bs []approve.Badge, prefix string) bool {
	for _, b := range bs {
		if strings.HasPrefix(b.Text, prefix) {
			return true
		}
	}
	return false
}
