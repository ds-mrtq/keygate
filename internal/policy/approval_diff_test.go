package policy

import (
	"slices"
	"testing"
)

func TestChangesFirstApproval(t *testing.T) {
	p := parseDiffPolicy(t, `grants:
  demo/prod/db:
    kind: oracle-wallet
    tns_alias: DEMO_PROD
    allow_commands: ["sql /@DEMO_PROD", "sql /@DEMO_PROD @report.sql"]
    ttl: 1h2m3s
  demo/blocked:
    approval: deny
`)
	got := Changes(nil, p)
	assertChangeText(t, got,
		`+ THÊM quyền dùng secret demo/prod/db
    lệnh được nhận secret:
      • sql /@DEMO_PROD
      • sql /@DEMO_PROD @report.sql
    cấp dạng: oracle-wallet, TNS DEMO_PROD
    duyệt: Hello/điện thoại
    hết hạn: 1 giờ 2 phút 3 giây`,
		`+ THÊM quyền dùng secret demo/blocked
    lệnh được nhận secret: (không lệnh nào)
    cấp dạng: theo kind của secret
    duyệt: luôn chặn
    hết hạn: không hết hạn`)
	if !got[0].Prod || got[1].Prod {
		t.Fatalf("unexpected production flags: %+v", got)
	}
}

func TestChangesApprovalDiff(t *testing.T) {
	old := parseDiffPolicy(t, `oracle:
  java: /opt/old/bin/java
  pki_jar: /opt/oracle/pki.jar
grants:
  demo/token:
    env_name: DEMO_TOKEN
    allow_commands: [curl --head, curl --silent]
    allow_as: [file, wallet]
  demo/retired:
    allow_commands: [curl]
  demo/unchanged:
    allow_commands: [curl]
`)
	cur := parseDiffPolicy(t, `oracle:
  java: /opt/new/bin/java
  tns_admin: /opt/tns
grants:
  demo/unchanged:
    allow_commands: [curl]
  demo/token:
    kind: file
    approval: device
    ttl: 45s
    max_runtime: 3m
    allow_commands: [curl --head, curl --fail]
`)
	got := Changes(old, cur)
	assertChangeText(t, got,
		`~ SỬA quyền dùng secret demo/token
    thêm lệnh: curl --fail
    bỏ lệnh: curl --silent
    cấp dạng: theo kind của secret DEMO_TOKEN → file
    duyệt: Hello/điện thoại → chữ ký điện thoại
    hết hạn: không hết hạn → 45 giây
    chạy tối đa: (không đặt) → 3 phút
    cho đổi dạng (--as): file, wallet → (bỏ)`,
		`- BỎ quyền dùng secret demo/retired (lệnh sẽ phải xin duyệt lại hoặc bị chặn)`,
		`~ SỬA công cụ Oracle (chương trình được cầm mật khẩu DB)
    java: /opt/old/bin/java → /opt/new/bin/java
    pki_jar: /opt/oracle/pki.jar → (trống)
    tns_admin: (trống) → /opt/tns`)
	if !slices.Equal(got[0].Commands, []string{"curl --head", "curl --fail"}) ||
		got[0].Approval != "chữ ký điện thoại" || got[0].TTL != "45 giây" {
		t.Errorf("modified grant does not carry current settings: %+v", got[0])
	}
	if !slices.Equal(got[1].Commands, []string{"curl"}) {
		t.Errorf("removed grant does not carry previous commands: %+v", got[1])
	}
}

func TestChangesIgnoresFormatting(t *testing.T) {
	old := parseDiffPolicy(t, "grants:\n  demo/token:\n    allow_commands: [curl]\n")
	cur := parseDiffPolicy(t, "grants:\n  'demo/token': # description\n    approval: user-presence\n    allow_commands: [ \"curl\" ]\n")
	if got := Changes(old, cur); len(got) != 0 {
		t.Fatalf("formatting-only edits produced changes: %+v", got)
	}
}

func TestChangesOverlappingWildcardReorder(t *testing.T) {
	old := parseDiffPolicy(t, `grants:
  team/*/db:
    allow_commands: ["sql /@QA"]
    approval: user-presence
  team/qa/*:
    allow_commands: [curl]
    approval: device
`)
	cur := parseDiffPolicy(t, `grants:
  team/qa/*:
    allow_commands: [curl]
    approval: device
  team/*/db:
    allow_commands: ["sql /@QA"]
    approval: user-presence
`)

	// Without vault secrets, the precedence swap itself is still reported.
	got := Changes(old, cur)
	assertChangeText(t, got,
		`~ SỬA quyền dùng secret team/qa/*
    ưu tiên wildcard: sau team/*/db → trước team/*/db`)

	// With a vault secret in the intersection, both the precedence swap and the affected secret are reported.
	gotWithSecrets := Changes(old, cur,
		SecretRef{Name: "team/qa/db", Env: "qa"},
		SecretRef{Name: "team/dev/db", Env: "dev"}, // still governed by team/*/db: must not appear
	)
	assertChangeText(t, gotWithSecrets,
		`~ SỬA quyền dùng secret team/qa/*
    ưu tiên wildcard: sau team/*/db → trước team/*/db`,
		`~ SỬA quyền dùng secret team/qa/db
    thêm lệnh: curl
    bỏ lệnh: sql /@QA
    quyền áp dụng: team/*/db → team/qa/*
    duyệt: Hello/điện thoại → chữ ký điện thoại`)

	// Non-overlapping equal-specificity wildcards swapping order produce no changes.
	disjointOld := parseDiffPolicy(t, "grants:\n  alpha/*:\n    allow_commands: [\"sql /@QA\"]\n  beta/*:\n    allow_commands: [curl]\n")
	disjointCur := parseDiffPolicy(t, "grants:\n  beta/*:\n    allow_commands: [curl]\n  alpha/*:\n    allow_commands: [\"sql /@QA\"]\n")
	if got := Changes(disjointOld, disjointCur, SecretRef{Name: "alpha/db"}, SecretRef{Name: "beta/db"}); len(got) != 0 {
		t.Fatalf("disjoint wildcard reorder produced changes: %+v", got)
	}

	// Overlapping wildcards with identical settings swapping order produce no changes.
	sameOld := parseDiffPolicy(t, "grants:\n  team/*/db:\n    allow_commands: [\"sql /@QA\"]\n  team/qa/*:\n    allow_commands: [\"sql /@QA\"]\n")
	sameCur := parseDiffPolicy(t, "grants:\n  team/qa/*:\n    allow_commands: [\"sql /@QA\"]\n  team/*/db:\n    allow_commands: [\"sql /@QA\"]\n")
	if got := Changes(sameOld, sameCur, SecretRef{Name: "team/qa/db"}); len(got) != 0 {
		t.Fatalf("identical wildcard reorder produced changes: %+v", got)
	}
}

func TestChangesExactGrantDeletionFallbackToWildcard(t *testing.T) {
	old := parseDiffPolicy(t, `grants:
  team/qa/db:
    allow_commands: ["sql /@QA"]
    approval: user-presence
  team/*:
    allow_commands: [curl]
    approval: device
    ttl: 2h
    max_runtime: 5m
`)
	cur := parseDiffPolicy(t, `grants:
  team/*:
    allow_commands: [curl]
    approval: device
    ttl: 2h
    max_runtime: 5m
`)

	got := Changes(old, cur, SecretRef{Name: "team/qa/db", Env: "qa"})
	assertChangeText(t, got,
		`- BỎ quyền dùng secret team/qa/db (rơi về grant wildcard team/*)
    lệnh được nhận secret (từ team/*):
      • curl
    cấp dạng: theo kind của secret
    duyệt: chữ ký điện thoại
    hết hạn: 2 giờ
    chạy tối đa: 5 phút`)
	if got[0].Fallback != "team/*" || got[0].Approval != "chữ ký điện thoại" || got[0].TTL != "2 giờ" {
		t.Fatalf("fallback metadata missing: %+v", got[0])
	}

	// Removing an explicit approval: deny exact grant while a wildcard matches must also report fallback.
	denyOld := parseDiffPolicy(t, "grants:\n  team/qa/db:\n    approval: deny\n  team/*:\n    allow_commands: [curl]\n")
	denyCur := parseDiffPolicy(t, "grants:\n  team/*:\n    allow_commands: [curl]\n")
	denyGot := Changes(denyOld, denyCur, SecretRef{Name: "team/qa/db", Env: "qa"})
	if len(denyGot) != 1 || denyGot[0].Op != ChangeDel || denyGot[0].Fallback != "team/*" {
		t.Fatalf("deleting explicit deny exact grant did not report wildcard fallback: %+v", denyGot)
	}

	// PROD secrets (by name or vault env) never fall back to wildcards.
	prodOld := parseDiffPolicy(t, "grants:\n  team/prod/db:\n    allow_commands: [\"sql /@QA\"]\n  team/*:\n    allow_commands: [curl]\n")
	prodCur := parseDiffPolicy(t, "grants:\n  team/*:\n    allow_commands: [curl]\n")
	prodGot := Changes(prodOld, prodCur)
	if len(prodGot) != 1 || prodGot[0].Fallback != "" {
		t.Fatalf("PROD secret by name must not report wildcard fallback: %+v", prodGot)
	}
	prodEnvGot := Changes(old, cur, SecretRef{Name: "team/qa/db", Env: "prod"})
	if len(prodEnvGot) != 1 || prodEnvGot[0].Fallback != "" {
		t.Fatalf("PROD secret by env must not report wildcard fallback: %+v", prodEnvGot)
	}

	// Falling back to a wildcard with approval: deny is still denied (no permissive fallback).
	denyWildOld := parseDiffPolicy(t, "grants:\n  team/qa/db:\n    allow_commands: [\"sql /@QA\"]\n  team/*:\n    approval: deny\n")
	denyWildCur := parseDiffPolicy(t, "grants:\n  team/*:\n    approval: deny\n")
	if denyWildGot := Changes(denyWildOld, denyWildCur); len(denyWildGot) != 1 || denyWildGot[0].Fallback != "" {
		t.Fatalf("approval: deny wildcard must not be reported as permissive fallback: %+v", denyWildGot)
	}
}

func TestChangesNarrowerWildcardDeletionAndDenyReorder(t *testing.T) {
	// Deleting a narrower wildcard causes a vault secret to fall back to a broader wildcard.
	old := parseDiffPolicy(t, "grants:\n  team/qa/*:\n    allow_commands: [\"sql /@QA\"]\n  team/*:\n    allow_commands: [curl]\n")
	cur := parseDiffPolicy(t, "grants:\n  team/*:\n    allow_commands: [curl]\n")
	got := Changes(old, cur, SecretRef{Name: "team/qa/db", Env: "qa"})
	assertChangeText(t, got,
		`- BỎ quyền dùng secret team/qa/* (lệnh sẽ phải xin duyệt lại hoặc bị chặn)`,
		`~ SỬA quyền dùng secret team/qa/db
    thêm lệnh: curl
    bỏ lệnh: sql /@QA
    quyền áp dụng: team/qa/* → team/*`)

	// Reordering a deny wildcard ahead of an overlapping allow wildcard transitions the secret to denied.
	denyOld := parseDiffPolicy(t, "grants:\n  team/*/db:\n    allow_commands: [\"sql /@QA\"]\n  team/qa/*:\n    approval: deny\n")
	denyCur := parseDiffPolicy(t, "grants:\n  team/qa/*:\n    approval: deny\n  team/*/db:\n    allow_commands: [\"sql /@QA\"]\n")
	denyGot := Changes(denyOld, denyCur, SecretRef{Name: "team/qa/db", Env: "qa"})
	assertChangeText(t, denyGot,
		`~ SỬA quyền dùng secret team/qa/*
    ưu tiên wildcard: sau team/*/db → trước team/*/db`,
		`~ SỬA quyền dùng secret team/qa/db
    bỏ lệnh: sql /@QA
    quyền áp dụng: team/*/db → (bị chặn)
    duyệt: Hello/điện thoại → luôn chặn`)
}

func parseDiffPolicy(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assertChangeText(t *testing.T, changes []Change, want ...string) {
	t.Helper()
	if len(changes) != len(want) {
		t.Fatalf("got %d changes, want %d: %+v", len(changes), len(want), changes)
	}
	for i, c := range changes {
		if got := c.Text(); got != want[i] {
			t.Errorf("change %d:\ngot:\n%s\nwant:\n%s", i, got, want[i])
		}
	}
}
