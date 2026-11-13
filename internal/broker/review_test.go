package broker

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPeerParts(t *testing.T) {
	cases := []struct{ in, who, chain string }{
		{`pid=12 exe=C:\Program Files\Go\kg.exe cha=bash.exe(5)<omp.exe(3)`, "kg.exe (pid 12)", "bash.exe(5) ← omp.exe(3)"},
		{"pid=7 uid=1000 exe=/usr/bin/kg", "kg (pid 7)", ""},
		{"pid=unavailable", "pid=unavailable", ""},
	}
	for _, c := range cases {
		if who, chain := peerParts(c.in); who != c.who || chain != c.chain {
			t.Errorf("%q: got %q, %q", c.in, who, chain)
		}
	}
}

func TestShortCmd(t *testing.T) {
	for in, want := range map[string]string{
		"python path:D:/repos/x/scripts/fetch_issues.py": "python fetch_issues.py",
		`"C:/a b/sql.exe" sha256:abc **`:                 "sql.exe ** (ghim hash)",
	} {
		if got := shortCmd(in); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
}

// The tray's Secret window: metadata only, and reveal/delete always ask Windows Hello, even inside
// an open work session.
func TestTraySecrets(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "ebs/test/a", "test")
	f.put("", "ht/prod/exact", "prod")
	f.put("", "solo", "dev")
	f.f_policy(basePolicy)
	ctx := context.Background()
	rows, err := f.b.SecretsForUI(ctx)
	if err != nil || len(rows) != 3 {
		t.Fatalf("%+v %v", rows, err)
	}
	by := map[string]SecretRow{}
	for _, r := range rows {
		by[r.Name] = r
	}
	if r := by["ebs/test/a"]; r.Group != "ebs" || r.Grant != "ebs/test/*" || r.Short != "sql /@HTTEST" || r.Prod {
		t.Fatalf("test row: %+v", r)
	}
	if r := by["ht/prod/exact"]; !r.Prod || r.Grant != "ht/prod/exact" {
		t.Fatalf("prod row: %+v", r)
	}
	if r := by["solo"]; r.Group != "(không nhóm)" || r.Grant != "" {
		t.Fatalf("solo row: %+v", r)
	}
	if err := f.b.StartSession(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	before := f.approvals.Load()
	if err := f.b.RevealFromUI(ctx, "solo"); err != nil || f.approvals.Load() != before+1 {
		t.Fatalf("reveal: %v approvals=%d", err, f.approvals.Load()-before)
	}
	if !strings.Contains(f.prompt.String(), "value-solo") {
		t.Fatal("value not shown on the broker's dialog")
	}
	f.refuse.Store(true)
	if _, err := f.b.DeleteFromUI(ctx, []string{"solo"}); err == nil {
		t.Fatal("delete without approval")
	}
	f.refuse.Store(false)
	before = f.approvals.Load()
	done, err := f.b.DeleteFromUI(ctx, []string{"solo", "ebs/test/a"})
	if err != nil || len(done) != 2 || f.approvals.Load() != before+1 {
		t.Fatalf("delete: %v %v approvals=%d", done, err, f.approvals.Load()-before)
	}
	if rows, _ := f.b.SecretsForUI(ctx); len(rows) != 1 || rows[0].Name != "ht/prod/exact" {
		t.Fatalf("left: %+v", rows)
	}
}

// Deleting from the tray never goes to the phone: with a paired phone and a locked screen it
// fails instead of publishing a request (a later phone decision could be reused by `kg delete`).
func TestTrayDeleteLocalOnly(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	r.put("", "d/x", "dev")
	if err := r.b.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.locked.Store(true)
	if _, err := r.b.DeleteFromUI(context.Background(), []string{"d/x"}); err == nil {
		t.Fatal("delete approved without this machine")
	}
	r.noPendingFor(600 * time.Millisecond)
	r.locked.Store(false)
	if rows, _ := r.b.SecretsForUI(context.Background()); len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
}

// A name whose display form differs from the stored one is flagged so the window cannot act on it.
func TestTraySecretsUnsafeName(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "a/b", "dev")
	f.put("", "a/b\u200b", "dev")
	rows, err := f.b.SecretsForUI(context.Background())
	if err != nil || len(rows) != 2 {
		t.Fatalf("%+v %v", rows, err)
	}
	for _, r := range rows {
		if !r.Unsafe || r.Name != "a/b" {
			t.Fatalf("row %+v", r)
		}
	}
}
