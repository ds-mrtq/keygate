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
