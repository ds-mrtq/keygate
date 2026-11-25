package broker

import (
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
	ov := policyOverview("policy.yaml", base, 3, "", st, cur, true, nil)
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
	if ov := policyOverview("policy.yaml", nil, 0, "", nil, cur, true, nil); !hasBadge(ov.Badges, "chưa áp dụng") || len(ov.Rows) != 4 {
		t.Fatalf("nothing applied: badges=%v rows=%d", ov.Badges, len(ov.Rows))
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
