//go:build kgtest

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"keygate/internal/approve"
	"keygate/internal/members"
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

func TestResolveConflictCommand(t *testing.T) {
	for _, choice := range []string{"device", "hash"} {
		t.Run(choice, func(t *testing.T) {
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
			r, err := st.Put("", record.Plain{Name: "test/conflict", Value: "fake-base"})
			st.Close()
			if err != nil {
				t.Fatal(err)
			}
			a.do(t, "sync")
			b.do(t, "sync")
			var keep string
			for i, app := range []*testApp{a, b} {
				st, err := app.openStore()
				if err != nil {
					t.Fatal(err)
				}
				r, err := st.Put(r.Item, record.Plain{Name: "test/conflict", Value: []string{"fake-local", "fake-peer"}[i]})
				if err != nil {
					st.Close()
					t.Fatal(err)
				}
				if i == 1 {
					keep = st.ID.Dev
					if choice == "hash" {
						keep, err = r.Hash()
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				st.Close()
			}
			a.do(t, "sync")
			b.do(t, "sync")
			a.do(t, "sync")
			commandFails(t, a, "", "resolve-conflict", "test/conflict", "--keep", "unknown")
			a.approver = approve.Func(func(context.Context, string) error { return approve.ErrNotVerified })
			commandFails(t, a, "", "resolve-conflict", "test/conflict", "--keep", keep)
			a.approver = approve.Func(func(context.Context, string) error { return nil })
			a.do(t, "resolve-conflict", "test/conflict", "--keep", keep)
			st, err = a.openStore()
			if err != nil {
				t.Fatal(err)
			}
			p, _, err := st.Get(r.Item)
			st.Close()
			if err != nil || p.Value != "fake-peer" {
				t.Fatal("wrong conflict head selected")
			}
			commandFails(t, a, "không có xung đột", "resolve-conflict", "test/conflict", "--keep", keep)
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

func TestCommandUsage(t *testing.T) {
	for _, args := range [][]string{{"grant"}, {"grant", "test/item", "--"}, {"grant", "--unknown"}, {"reveal"}, {"reveal", "--unknown"}, {"recover", "--unknown"}, {"device", "revoke"}, {"device", "revoke", "--unknown"}, {"approve", "--unknown"}, {"resolve-conflict"}, {"resolve-conflict", "--unknown"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) { commandFails(t, newTestApp(t, t.TempDir()), "", args...) })
	}
}
