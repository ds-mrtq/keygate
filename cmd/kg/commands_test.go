//go:build kgtest

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"keygate/internal/api"
	"keygate/internal/approve"
	"keygate/internal/audit"
	"keygate/internal/members"
	"keygate/internal/policy"
	"keygate/internal/record"
	"keygate/internal/store"
)

const commandMaster = "fake command test password"

func commandVault(t *testing.T) (*testApp, string, string) {
	t.Helper()
	t.Setenv("KG_DEVKEY_BACKEND", "plain")
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	a := newTestApp(t, filepath.Join(root, "home"))
	a.secrets = []string{commandMaster, commandMaster}
	out := a.do(t, "init", "--label", "test", "--dir", shared)
	m := regexp.MustCompile(`(?m)^\s+([A-Z2-7]{4}(?:-[A-Z2-7]{4})+)\s*$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatal("missing paper key")
	}
	return a, m[1], shared
}

func commandFails(t *testing.T, a *testApp, want string, args ...string) {
	t.Helper()
	a.out.Reset()
	a.errb.Reset()
	if a.run(args) == 0 {
		t.Fatal("command unexpectedly succeeded")
	}
	if !strings.Contains(a.errb.String(), want) {
		t.Fatalf("missing expected error category %q", want)
	}
}

func TestRecoverCommand(t *testing.T) {
	a, paper, shared := commandVault(t)
	for _, tc := range []struct{ name, password, key string }{
		{"password", "wrong fake password", paper},
		{"paper", commandMaster, "invalid"},
		{"success", commandMaster, paper},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newTestApp(t, filepath.Join(t.TempDir(), "recovered"))
			b.secrets = []string{tc.password, tc.key}
			err := b.cmdRecover([]string{"--from", shared, "--label", "replacement"})
			if tc.name != "success" {
				if err == nil {
					t.Fatal("invalid credentials accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			a.do(t, "sync")
			if b.do(t, "fingerprint") != a.do(t, "fingerprint") {
				t.Fatal("recovered state differs")
			}
			commandFails(t, b, "đã có vault", "recover", "--from", shared, "--label", "again")
		})
	}
	commandFails(t, a, "dùng:", "recover")
	commandFails(t, newTestApp(t, t.TempDir()), "kênh không có vault", "recover", "--from", t.TempDir(), "--label", "test")
	commandFails(t, newTestApp(t, t.TempDir()), "flag provided but not defined", "recover", "--from", shared, "--label", "test", "--pin", "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
	commandFails(t, newTestApp(t, t.TempDir()), "--members-file", "recover", "--from", "https://example.invalid", "--label", "test")
}

func TestDeviceRevokeCommand(t *testing.T) {
	a, paper, _ := commandVault(t)
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	a.secrets = []string{commandMaster, paper}
	keys, err := a.ownerKeys(st)
	if err != nil {
		t.Fatal(err)
	}
	other, phone := store.NewIdentity("other"), store.NewIdentity("phone")
	if err := st.AddDevice(keys.OwnerPriv, other.Public()); err != nil {
		t.Fatal(err)
	}
	p := phone.Public()
	p.Role = members.RoleApprover
	if err := st.AddDevice(keys.OwnerPriv, p); err != nil {
		t.Fatal(err)
	}
	self := st.ID.Dev
	if _, err := st.Put("", record.Plain{Name: "test/item", Value: "fake-value"}); err != nil {
		t.Fatal(err)
	}
	epoch := st.Epoch()
	st.Close()
	for id, want := range map[string]string{"unknown": "not an active device", self: "cannot revoke itself"} {
		a.secrets = []string{commandMaster, paper}
		commandFails(t, a, want, "device", "revoke", id)
	}
	a.approver = approve.Func(func(context.Context, string) error { return approve.ErrNotVerified })
	commandFails(t, a, "", "device", "revoke", phone.Dev)
	a.approver = approve.Func(func(context.Context, string) error { return nil })
	a.do(t, "device", "revoke", phone.Dev, "--reason", "test")
	a.secrets = []string{commandMaster, paper}
	a.do(t, "device", "revoke", other.Dev)
	st, err = a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if !st.Members().Devices[phone.Dev].Revoked || !st.Members().Devices[other.Dev].Revoked || st.Epoch() != epoch+1 {
		t.Fatal("incorrect revocation state")
	}
	if _, _, err := st.Get(st.List()[0].Item); err != nil {
		t.Fatal(err)
	}
}

func TestApproveCommand(t *testing.T) {
	a, _, _ := commandVault(t)
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	id := st.ID
	vault := st.Vault()
	st.Close()
	ch, err := approve.NewChallenge(vault, "test/item", "go version", time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out := a.do(t, "approve", ch.Encode())
	if _, err := approve.Verify(ch, strings.TrimSpace(out), "another-device", map[string]ed25519.PublicKey{id.Dev: id.EdPub}, time.Now()); err != nil {
		t.Fatal(err)
	}
	a.approver = approve.Func(func(context.Context, string) error { return approve.ErrNotVerified })
	commandFails(t, a, "", "approve", ch.Encode())
	if a.out.Len() != 0 {
		t.Fatal("denial emitted signature")
	}
	ch.Expires = time.Now().Add(-time.Minute).Unix()
	if !errors.Is(a.cmdApprove([]string{ch.Encode()}), approve.ErrExpired) {
		t.Fatal("expired challenge accepted")
	}
	commandFails(t, a, "", "approve", "invalid")
	commandFails(t, a, "dùng:", "approve")
}

func TestUserPresencePlatform(t *testing.T) {
	a := newTestApp(t, t.TempDir())
	a.approver = nil
	t.Setenv("KG_TEST_APPROVE", "allow")
	if err := a.userPresence("test"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KG_TEST_APPROVE", "deny")
	if !errors.Is(a.userPresence("test"), approve.ErrNotVerified) {
		t.Fatal("denial ignored")
	}
}

func TestListAndResolveConflictCommands(t *testing.T) {
	for _, choice := range []string{"device", "hash"} {
		t.Run(choice, func(t *testing.T) {
			const name = "test/conflict"
			values := []string{"fake-local", "fake-peer"}
			a, paper, shared := commandVault(t)
			b := newTestApp(t, filepath.Join(t.TempDir(), "peer"))
			out := b.do(t, "device", "request", "--label", "peer")
			code := regexp.MustCompile(`(?m)^([A-Z2-7]{40,})$`).FindStringSubmatch(out)
			if code == nil {
				t.Fatal("missing request code")
			}
			a.secrets = []string{commandMaster, paper}
			a.lines = []string{"yes"}
			a.do(t, "device", "add", code[1])
			cfg, err := store.ReadConfig(a.home)
			if err != nil {
				t.Fatal(err)
			}
			pin, err := genesisPin(a.home)
			if err != nil {
				t.Fatal(err)
			}
			b.do(t, "sync", "--via", "dir", "--dir", shared, "--vault", cfg.Vault, "--pin", pin)
			st, err := a.openStore()
			if err != nil {
				t.Fatal(err)
			}
			r, err := st.Put("", record.Plain{Name: name, Value: "fake-base"})
			st.Close()
			if err != nil {
				t.Fatal(err)
			}
			a.do(t, "sync")
			b.do(t, "sync")
			var keep string
			var wantHeads []string
			for i, app := range []*testApp{a, b} {
				st, err := app.openStore()
				if err != nil {
					t.Fatal(err)
				}
				head, err := st.Put(r.Item, record.Plain{Name: name, Value: values[i]})
				st.Close()
				if err != nil {
					t.Fatal(err)
				}
				hash, err := head.Hash()
				if err != nil {
					t.Fatal(err)
				}
				wantHeads = append(wantHeads, fmt.Sprintf("thiết bị %s seq %d %s %s", head.Dev, head.Seq, head.Op, hash))
				if i == 1 {
					keep = head.Dev
					if choice == "hash" {
						keep = hash
					}
				}
			}
			slices.Sort(wantHeads)
			a.do(t, "sync")
			b.do(t, "sync")
			a.do(t, "sync")

			checkConflicts := func(t *testing.T, app *testApp) {
				t.Helper()
				out := app.do(t, "conflicts")
				for _, value := range values {
					if strings.Contains(out, value) || strings.Contains(app.errb.String(), value) {
						t.Fatal("conflict listing exposed a secret value")
					}
				}
				lines := strings.Split(strings.TrimSpace(out), "\n")
				if lines[0] != name {
					t.Fatalf("conflict listing did not name %q", name)
				}
				heads := lines[1:]
				for i := range heads {
					heads[i] = strings.TrimSpace(heads[i])
				}
				slices.Sort(heads)
				if !slices.Equal(heads, wantHeads) {
					t.Fatalf("conflict heads = %q, want %q", heads, wantHeads)
				}
			}
			t.Run("local listing", func(t *testing.T) { checkConflicts(t, a) })
			t.Run("broker listing", func(t *testing.T) {
				b.startBroker(t)
				checkConflicts(t, b)
			})

			commandFails(t, a, "", "resolve-conflict", name, "--keep", "unknown")
			a.approver = approve.Func(func(context.Context, string) error { return approve.ErrNotVerified })
			commandFails(t, a, "", "resolve-conflict", name, "--keep", keep)
			a.approver = approve.Func(func(context.Context, string) error { return nil })
			a.do(t, "resolve-conflict", name, "--keep", keep)
			st, err = a.openStore()
			if err != nil {
				t.Fatal(err)
			}
			p, _, err := st.Get(r.Item)
			st.Close()
			if err != nil || p.Value != values[1] {
				t.Fatal("wrong conflict head selected")
			}
			if got := strings.TrimSpace(a.do(t, "conflicts")); got != "Không có xung đột." {
				t.Fatal("resolved conflict was still listed")
			}
			commandFails(t, a, "không có xung đột", "resolve-conflict", name, "--keep", keep)
		})
	}
}

func TestGrantRevealCommands(t *testing.T) {
	a, _, _ := commandVault(t)
	var deny atomic.Bool
	allowed := a.approver
	a.approver = approve.Func(func(ctx context.Context, prompt string) error {
		if deny.Load() {
			return approve.ErrNotVerified
		}
		return allowed.Approve(ctx, prompt)
	})
	const value = "fake-command-secret-value"
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put("", record.Plain{Name: "test/item", Kind: "env", EnvName: "KG_TEST_TOKEN", Value: value}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := os.WriteFile(filepath.Join(a.home, "policy.yaml"), []byte("grants:\n  test/item:\n    kind: env\n    allow_commands: [\"go version\"]\n    approval: user-presence\n    ttl: 1ms\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a.startBroker(t)
	a.do(t, "policy", "apply")
	a.do(t, "session", "end")
	// Reveal is independently human-approved, not gated by a command grant.
	a.do(t, "reveal", "test/item")
	if strings.Contains(a.out.String()+a.errb.String(), value) {
		t.Fatal("reveal leaked over client output")
	}
	commandFails(t, a, "", "reveal", "missing")
	a.do(t, "grant", "test/item", "--", "go", "version")
	a.mu.Lock()
	before := a.approvals
	a.mu.Unlock()
	time.Sleep(10 * time.Millisecond)
	a.do(t, "grant", "test/item", "--", "go", "version")
	a.mu.Lock()
	after := a.approvals
	a.mu.Unlock()
	if after <= before {
		t.Fatal("expired grant reused without approval")
	}
	commandFails(t, a, "", "grant", "test/item", "--", "sh", "-c", "true")
	commandFails(t, a, "", "grant", "missing", "--", "go", "version")
	deny.Store(true)
	commandFails(t, a, "", "reveal", "test/item")
	if strings.Contains(a.out.String()+a.errb.String(), value) {
		t.Fatal("denied reveal leaked value")
	}
	a.do(t, "lock")
}

func TestResolveCLIRequiresPinnedPolicyAndMasksRenderedValue(t *testing.T) {
	a, _, _ := commandVault(t)
	const name, value = "test/template", "fake-template-value"
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Put("", record.Plain{Name: name, Kind: "template", Value: value})
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	const template = "value=${secret:" + name + "}\n"
	path := filepath.Join(t.TempDir(), "test.conf")
	if err := os.WriteFile(path, []byte(template), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.home, "policy.yaml"), []byte(`grants:
  test/template:
    kind: template
    allow_commands: ["go run ./testdata/printenv --read-file KG_TEST_RESOLVED"]
    approval: user-presence
`), 0o600); err != nil {
		t.Fatal(err)
	}
	a.startBroker(t)
	child := []string{"--", "go", "run", "./testdata/printenv", "--read-file", "KG_TEST_RESOLVED"}
	commandFails(t, a, "kg resolve <file>", append([]string{"resolve"}, child...)...)
	args := append([]string{"resolve", path, "--into", "KG_TEST_RESOLVED"}, child...)
	commandFails(t, a, policy.ErrNoPin.Error(), args...)
	if a.out.Len() != 0 || strings.Contains(a.errb.String(), value) {
		t.Fatal("unapproved template run produced child output or disclosed the value")
	}
	a.do(t, "policy", "apply")
	out := a.do(t, args...)
	if strings.TrimSpace(out) != "value=[kg:"+name+"]" || strings.Contains(out+a.errb.String(), value) {
		t.Fatal("resolved file output was not rendered and redacted")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != template {
		t.Fatal("resolve changed the source template")
	}
}

func TestSyncCLIRequiresMatchingChannelFingerprints(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	a, _, _ := commandVault(t)
	gitDir := t.TempDir()
	if out, err := exec.Command(git, "-C", gitDir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("could not initialize local git channel: %v: %s", err, out)
	}
	a.do(t, "sync", "--via", "git", "--git-dir", gitDir)

	// The next sync will publish this record to dir, leaving git one record behind.
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Put("", record.Plain{Name: "test/sync", Kind: "env", EnvName: "KG_TEST_TOKEN", Value: "fake-sync-value"})
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	a.startBroker(t)

	args := []string{"sync", "--via", "dir", "--verify-via", "git"}
	commandFails(t, a, store.ErrFork.Error(), args...)
	if a.out.Len() != 0 {
		t.Fatalf("failed verification printed a success summary: %q", a.out.String())
	}
	if !strings.Contains(a.errb.String(), "dir says") || !strings.Contains(a.errb.String(), "git says") {
		t.Fatalf("mismatch did not identify both channels: %q", a.errb.String())
	}
	const verified = "Đã đối chiếu fingerprint với kênh git: khớp."
	if out := a.do(t, "sync", "--via", "git"); !strings.Contains(out, "Đồng bộ qua git:") || strings.Contains(out, "Đã đối chiếu") {
		t.Fatalf("expected git sync without verification, got %q", out)
	}
	if out := a.do(t, args...); !strings.Contains(out, "Đồng bộ qua dir:") || !strings.Contains(out, verified) {
		t.Fatalf("expected successful dir sync verified against git, got %q", out)
	}
}

func TestMCPUsesBrokerWithoutExposingValues(t *testing.T) {
	a, _, _ := commandVault(t)
	const name, env, value = "test/mcp", "test", "fake-mcp-secret-value"
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Put("", record.Plain{Name: name, Kind: "env", Env: env, EnvName: "KG_TEST_TOKEN", Value: value})
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	const rules = `grants:
  test/mcp:
    kind: env
    allow_commands: ["go version"]
    approval: user-presence
    ttl: 1h
`
	if err := os.WriteFile(filepath.Join(a.home, "policy.yaml"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	var deny atomic.Bool
	var refusals atomic.Int32
	allow := a.approver
	a.approver = approve.Func(func(ctx context.Context, prompt string) error {
		if deny.Load() {
			refusals.Add(1)
			return approve.ErrNotVerified
		}
		return allow.Approve(ctx, prompt)
	})
	a.startBroker(t)
	a.do(t, "policy", "apply")
	a.do(t, "session", "end")
	deny.Store(true)

	client := newTestApp(t, a.home)
	call := func(id, params string, wantErr bool) string {
		t.Helper()
		client.stdin = strings.NewReader(fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"tools/call","params":%s}`+"\n", id, params))
		out := client.do(t, "mcp")
		if strings.Contains(out, value) || strings.Contains(client.errb.String(), value) {
			t.Fatal("MCP exposed a secret value")
		}
		var reply struct {
			JSONRPC string `json:"jsonrpc"`
			ID      string `json:"id"`
			Result  *struct {
				IsError *bool `json:"isError"`
				Content []struct{ Type, Text string }
			}
			Error json.RawMessage
		}
		if err := json.Unmarshal([]byte(out), &reply); err != nil {
			t.Fatalf("invalid MCP response: %v", err)
		}
		if reply.JSONRPC != "2.0" || reply.ID != id || reply.Error != nil || reply.Result == nil {
			t.Fatalf("wrong MCP response envelope for %q: %s", id, out)
		}
		r := reply.Result
		if r.IsError == nil || *r.IsError != wantErr || len(r.Content) != 1 || r.Content[0].Type != "text" {
			t.Fatalf("wrong MCP tool response for %q: %s", id, out)
		}
		return r.Content[0].Text
	}
	var list []api.SecretInfo
	text := call("list", `{"name":"list_secrets"}`, false)
	if err := json.Unmarshal([]byte(text), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != name || list[0].Env != env || list[0].Kind != "env" {
		t.Fatalf("MCP list returned wrong metadata: %s", text)
	}
	text = call("grant", `{"name":"request_grant","arguments":{"secret":"test/mcp","command":["go","version"]}}`, true)
	if refusals.Load() != 1 || !strings.Contains(text, approve.ErrNotVerified.Error()) {
		t.Fatalf("MCP did not report the human refusal: %q (refusals: %d)", text, refusals.Load())
	}
	grants, err := client.client().Grants(context.Background())
	if err != nil || len(grants) != 0 {
		t.Fatalf("after denying the request, got %d active grants (err=%v)", len(grants), err)
	}
}

func TestAuditRejectsDamagedLedger(t *testing.T) {
	a, _, _ := commandVault(t)
	path := filepath.Join(a.home, "audit", "ledger.jsonl")
	anchor := filepath.Join(a.home, "state", "audit.head")
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	ledger := audit.Open(path, anchor, st.LocalMacKey())
	st.Close()
	const name, changed = "test/synthetic-audit-entry", "test/changed-audit-entry"
	if err := ledger.Append(audit.Entry{Event: audit.EvGrant, Secret: name}); err != nil {
		t.Fatal(err)
	}
	if out := a.do(t, "audit", "verify"); !strings.Contains(out, "Audit hợp lệ: 1 dòng") {
		t.Fatalf("expected one verified entry, got %q", out)
	}
	if out := a.do(t, "audit", "show"); !strings.Contains(out, name) {
		t.Fatalf("expected a visible entry before ledger damage, got %q", out)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(name)) {
		t.Fatal("expected synthetic entry in ledger fixture")
	}
	if err := os.WriteFile(path, bytes.Replace(raw, []byte(name), []byte(changed), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"verify", "show"} {
		t.Run(operation, func(t *testing.T) {
			commandFails(t, a, "audit KHÔNG hợp lệ", "audit", operation)
			if a.out.Len() != 0 || strings.Contains(a.errb.String(), name) || strings.Contains(a.errb.String(), changed) {
				t.Fatal("failed audit command printed a success message or ledger content")
			}
		})
	}
}

func TestStatusReportsApprovalState(t *testing.T) {
	a, _, _ := commandVault(t)
	const name, value = "test/status", "fake-status-secret-value"
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Put("", record.Plain{Name: name, Kind: "env", EnvName: "KG_TEST_TOKEN", Value: value})
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(a.home, "policy.yaml")
	const policyBase = `grants:
  test/status:
    kind: env
    allow_commands: ["go version"]
    approval: user-presence
    ttl: `
	writePolicy := func(ttl string) {
		t.Helper()
		if err := os.WriteFile(policyPath, []byte(policyBase+ttl+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy("1h")
	a.startBroker(t)
	a.do(t, "policy", "apply")
	a.do(t, "session", "end")

	status := func(want ...string) string {
		t.Helper()
		out := a.do(t, "status")
		if strings.Contains(out, value) || strings.Contains(a.errb.String(), value) {
			t.Fatal("status exposed a secret value")
		}
		for _, text := range want {
			if !strings.Contains(out, text) {
				t.Fatalf("status missing %q, got %q", text, out)
			}
		}
		return out
	}
	const closed = "Phiên làm việc: không (mỗi grant hỏi duyệt một lần)"
	const pinned = "Policy: khớp pin |"
	status("Broker: đã mở |", closed, pinned)

	a.do(t, "session", "start")
	a.do(t, "grant", name, "--", "go", "version")
	const open = "Phiên làm việc: ĐANG MỞ "
	status("Broker: đã mở |", open, pinned, "Grant: "+name+" | go version | session | hết hạn ")

	writePolicy("2h") // The policy changed without being re-pinned.
	out := status("Broker: đã mở |", open, "Policy: KHÔNG hợp lệ (mọi grant bị từ chối) |")
	if strings.Contains(out, pinned) {
		t.Fatal("status described the changed policy as pinned")
	}

	a.do(t, "lock")
	out = status("Broker: ĐÃ KHÓA |", closed)
	if strings.Contains(out, open) || strings.Contains(out, "Grant: "+name) {
		t.Fatal("status still showed an open session or its grant after locking")
	}
}

func TestGrantsListAndRevokeCommands(t *testing.T) {
	a, _, _ := commandVault(t)
	const value = "fake-grants-secret-value"
	names := []string{"test/first", "test/second"}
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if _, err := st.Put("", record.Plain{Name: name, Kind: "env", EnvName: "KG_TEST_TOKEN", Value: value}); err != nil {
			st.Close()
			t.Fatal(err)
		}
	}
	st.Close()
	pol := "grants:\n  'test/*':\n    kind: env\n    allow_commands: [\"go version\"]\n    approval: user-presence\n"
	if err := os.WriteFile(filepath.Join(a.home, "policy.yaml"), []byte(pol), 0600); err != nil {
		t.Fatal(err)
	}
	a.startBroker(t)
	a.do(t, "policy", "apply")
	a.do(t, "session", "end")
	for _, name := range names {
		a.do(t, "grant", name, "--", "go", "version")
	}

	assertGrants := func(want ...string) {
		t.Helper()
		out := a.do(t, "grants")
		if strings.Contains(out+a.errb.String(), value) {
			t.Fatal("grant listing exposed a secret value")
		}
		if len(want) == 0 {
			if !strings.Contains(out, "Không có grant nào") {
				t.Fatalf("expected empty grant list, got %q", out)
			}
			return
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) != len(want)+1 {
			t.Fatalf("want %d grant rows, got %q", len(want), out)
		}
		got := make([]string, 0, len(want))
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) == 0 || !strings.Contains(line, "go version") ||
				!slices.Contains(fields, "user-presence") || !slices.Contains(fields, "by=hello") ||
				fields[len(fields)-1] != "true" {
				t.Fatalf("want an explicitly approved, durable grant row, got %q", line)
			}
			got = append(got, fields[0])
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Fatalf("grant names = %v, want %v", got, want)
		}
	}
	approvalCount := func() int {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.approvals
	}
	before := approvalCount()
	assertGrants(names...)
	commandFails(t, a, "kg grants revoke", "grants", "revoke")
	commandFails(t, a, "kg grants revoke", "grants", "revoke", names[0], "--all")
	commandFails(t, a, "kg grants revoke", "grants", "revoke", names[0], names[1])
	assertGrants(names...)

	if out := a.do(t, "grants", "revoke", names[0]); !strings.Contains(out, "thu hồi 1 grant") {
		t.Fatalf("expected one revoked grant, got %q", out)
	}
	assertGrants(names[1])
	a.do(t, "grant", names[1], "--", "go", "version")
	if after := approvalCount(); after != before {
		t.Fatalf("listing or revoking a different grant asked for %d approvals, want none", after-before)
	}
	a.do(t, "grant", names[0], "--", "go", "version")
	if after := approvalCount(); after != before+1 {
		t.Fatalf("requesting the revoked grant asked for %d approvals, want one", after-before)
	}

	a.do(t, "lock")
	assertGrants(names...)
	if out := a.do(t, "grants", "revoke", "--all"); !strings.Contains(out, "thu hồi 2 grant") {
		t.Fatalf("expected both grants to be revoked, got %q", out)
	}
	assertGrants()
	status, err := a.client().Status(context.Background())
	if err != nil || status.Unlocked {
		t.Fatalf("vault must stay locked during grant revocation: unlocked=%t, err=%v", status.Unlocked, err)
	}
	if after := approvalCount(); after != before+1 {
		t.Fatalf("grant revocation while locked asked for %d approvals, want none", after-(before+1))
	}
}

func TestImportDotenvCommand(t *testing.T) {
	a, _, _ := commandVault(t)
	var deny atomic.Bool
	a.approver = approve.Func(func(context.Context, string) error {
		if deny.Load() {
			return approve.ErrNotVerified
		}
		return nil
	})
	a.startBroker(t)

	path := filepath.Join(t.TempDir(), ".env")
	write := func(contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checkFile := func(want string) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatal("unexpected dotenv contents")
		}
	}
	checkNoValues := func() {
		t.Helper()
		if strings.Contains(a.out.String()+a.errb.String(), "fake-dotenv-") {
			t.Fatal("CLI exposed a dotenv value or unparsed line")
		}
	}

	const original = "SAME_KEY=fake-dotenv-match\nDIFF_KEY=fake-dotenv-before\nEXTRA_KEY=fake-dotenv-extra\n"
	write(original)
	empty := a.do(t, "fingerprint")
	deny.Store(true)
	commandFails(t, a, "bị từ chối", "import", "--dotenv", path, "--prefix", "test/", "--rewrite")
	checkNoValues()
	checkFile(original)
	if a.do(t, "fingerprint") != empty {
		t.Fatal("denied import changed the vault")
	}
	deny.Store(false)
	a.do(t, "import", "--dotenv", path, "--prefix", "test/")
	checkNoValues()
	checkFile(original)

	const changed = "SAME_KEY=fake-dotenv-match\r\nDIFF_KEY=fake-dotenv-after # keep\r\nNEW_KEY=fake-dotenv-new\r\nfake-dotenv-unparsed\r\n"
	write(changed)
	before := a.do(t, "fingerprint")
	compare := []string{"import", "--dotenv", path, "--prefix", "test/", "--compare"}
	deny.Store(true)
	commandFails(t, a, "bị từ chối", compare...)
	checkNoValues()
	deny.Store(false)
	out := a.do(t, compare...)
	checkNoValues()
	rows := strings.Split(strings.TrimSpace(out), "\n")
	for i, row := range rows {
		rows[i] = strings.Join(strings.Fields(row), " ")
	}
	slices.Sort(rows)
	wantRows := []string{"diff test/diff-key", "extra test/extra-key", "missing test/new-key", "same test/same-key", "unparsed line 4"}
	if !slices.Equal(rows, wantRows) {
		t.Errorf("compare output: got %q, want %q", rows, wantRows)
	}
	checkFile(changed)
	if a.do(t, "fingerprint") != before {
		t.Fatal("compare changed the vault")
	}

	a.do(t, "import", "--dotenv", path, "--prefix", "test/", "--rewrite")
	checkNoValues()
	checkFile("SAME_KEY=${secret:test/same-key}\r\nDIFF_KEY=${secret:test/diff-key} # keep\r\nNEW_KEY=${secret:test/new-key}\r\nfake-dotenv-unparsed\r\n")
}

func TestDeleteBatchCommand(t *testing.T) {
	a, _, _ := commandVault(t)
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"test/one", "test/two", "test/keep"} {
		if _, err := st.Put("", record.Plain{Name: name, Kind: "env", EnvName: "KG_TEST_TOKEN", Value: "fake-delete-value"}); err != nil {
			st.Close()
			t.Fatal(err)
		}
	}
	st.Close()
	var deny atomic.Bool
	a.approver = approve.Func(func(context.Context, string) error {
		if deny.Load() {
			return approve.ErrNotVerified
		}
		return nil
	})
	a.startBroker(t)
	before := a.do(t, "fingerprint")
	commandFails(t, a, "test/missing", "delete", "test/one", "test/missing")
	if a.do(t, "fingerprint") != before {
		t.Fatal("delete with an unknown name changed the vault")
	}
	deny.Store(true)
	commandFails(t, a, "bị từ chối", "delete", "test/one", "test/two")
	if a.do(t, "fingerprint") != before {
		t.Fatal("denied delete changed the vault")
	}
	deny.Store(false)
	if out := a.do(t, "delete", "test/one", "test/two"); !strings.Contains(out, "2 secret: test/one, test/two") {
		t.Fatalf("incorrect deletion summary: %q", out)
	}
	if out := a.do(t, "list"); strings.Contains(out, "test/one") || strings.Contains(out, "test/two") || !strings.Contains(out, "test/keep") {
		t.Fatalf("delete did not remove exactly the requested names: %q", out)
	}
}

func TestCopyAndCompareCommands(t *testing.T) {
	a, _, _ := commandVault(t)
	st, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []record.Plain{
		{Name: "src/one", Value: "fake-copy-value-one", Kind: "env", Env: "dev", EnvName: "ORIGINAL_ONE"},
		{Name: "src/two", Value: "fake-copy-value-two", Kind: "env", Env: "test", EnvName: "ORIGINAL_TWO"},
	} {
		if _, err := st.Put("", source); err != nil {
			st.Close()
			t.Fatal(err)
		}
	}
	st.Close()
	var deny atomic.Bool
	a.approver = approve.Func(func(context.Context, string) error {
		if deny.Load() {
			return approve.ErrNotVerified
		}
		return nil
	})
	a.startBroker(t)
	a.do(t, "session", "start")
	status, err := a.client().StatusFull(context.Background())
	if err != nil || !status.Session {
		t.Fatalf("copy and comparison must be tested in a live work session: %v", err)
	}

	checkNoValues := func() {
		t.Helper()
		if strings.Contains(a.out.String()+a.errb.String(), "fake-copy-value-") {
			t.Fatal("CLI exposed a source or copied secret value")
		}
	}
	const override = "COPIED_TOKEN"
	copyArgs := []string{"cp", "src/one", "dst/one", "src/two", "dst/two", "--env-name", override}
	before := a.do(t, "fingerprint")
	deny.Store(true)
	commandFails(t, a, "bị từ chối", copyArgs...)
	checkNoValues()
	commandFails(t, a, "bị từ chối", "same", "src/one", "src/two")
	checkNoValues()
	deny.Store(false)
	commandFails(t, a, "không ghi đè", "cp", "src/one", "dst/one", "src/one", "src/two")
	commandFails(t, a, `"PATH" bị cấm`, "cp", "src/one", "dst/one", "--env-name", "PATH")
	if a.do(t, "fingerprint") != before {
		t.Fatal("refused copies changed the vault")
	}

	out := a.do(t, copyArgs...)
	checkNoValues()
	if !strings.Contains(out, "2 secret: dst/one, dst/two") {
		t.Fatalf("wrong batch-copy summary: %q", out)
	}
	out = a.do(t, "same", "src/one", "dst/one", "dst/two")
	checkNoValues()
	if got := strings.Join(strings.Fields(out), " "); got != "same src/one vs dst/one diff src/one vs dst/two" {
		t.Fatalf("wrong comparison verdicts: %q", out)
	}
	out = a.do(t, "same", "src/two", "dst/two")
	checkNoValues()
	if got := strings.Join(strings.Fields(out), " "); got != "same src/two vs dst/two" {
		t.Fatalf("second copy did not match its source: %q", out)
	}

	a.do(t, "lock")
	st, err = a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, name := range []string{"dst/one", "dst/two"} {
		info, err := st.FindByName(name)
		if err != nil {
			t.Fatal(err)
		}
		p, _, err := st.Get(info.Item)
		if err != nil || p.EnvName != override {
			t.Fatalf("%s did not receive the env-name override: %v", name, err)
		}
	}
}

func TestHookCheckCommand(t *testing.T) {
	const (
		home       = "/synthetic/keygate-vault"
		marker     = "fake-private-filename"
		allowed    = `{"tool_name":"Read","tool_input":{"file_path":"README.md"}}`
		blocked    = `{"tool_name":"Read","tool_input":{"file_path":"` + home + `/` + marker + `.txt"}}`
		inputLimit = 4 << 20
	)
	atLimit := allowed + strings.Repeat(" ", inputLimit-len(allowed))

	for _, tc := range []struct {
		name     string
		input    io.Reader
		wantExit int
		wantDiag string
	}{
		{"allowed", strings.NewReader(allowed), 0, ""},
		{"allowed at size limit", strings.NewReader(atLimit), 0, ""},
		{"blocked vault path", strings.NewReader(blocked), 2, "Chặn: truy cập thư mục kho khóa KeyGate"},
		{"malformed JSON", strings.NewReader(`{"tool_name":"Read"`), 2, "hook: invalid JSON"},
		{"over size limit", strings.NewReader(atLimit + " "), 2, "đầu vào quá lớn"},
		{"read failure after valid JSON", io.MultiReader(strings.NewReader(allowed), iotest.ErrReader(errors.New("test read failure"))), 2, "test read failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestApp(t, home)
			a.stdin = tc.input
			got := a.run([]string{"hook", "check"})
			if got != tc.wantExit {
				t.Errorf("hook check exit = %d, want %d", got, tc.wantExit)
			}
			if a.out.Len() != 0 {
				t.Error("hook check unexpectedly wrote to stdout")
			}
			diag := a.errb.String()
			if tc.wantDiag == "" {
				if diag != "" {
					t.Error("allowed input produced a diagnostic")
				}
			} else if !strings.Contains(diag, tc.wantDiag) {
				t.Errorf("stderr missing diagnostic %q", tc.wantDiag)
			}
			if strings.Contains(diag, marker) {
				t.Error("stderr echoed a protected filename")
			}
		})
	}
}

func TestCommandUsage(t *testing.T) {
	for _, args := range [][]string{{"grant"}, {"grant", "test/item", "--"}, {"grant", "--unknown"}, {"reveal"}, {"reveal", "--unknown"}, {"recover", "--unknown"}, {"device", "revoke"}, {"device", "revoke", "--unknown"}, {"approve", "--unknown"}, {"resolve-conflict"}, {"resolve-conflict", "--unknown"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) { commandFails(t, newTestApp(t, t.TempDir()), "", args...) })
	}
}
