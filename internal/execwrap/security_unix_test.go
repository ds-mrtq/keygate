//go:build !windows

package execwrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keygate/internal/redact"
)

func testScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nset -eu\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertEmptyRunDir(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 0 {
		t.Fatalf("temporary material remains: entries=%d err=%v", len(ents), err)
	}
}

func TestChildEnvironmentIsolation(t *testing.T) {
	const secret = "fake-secret-XYZ"
	t.Setenv("KG_TOKEN", "fake-parent-token")
	t.Setenv("BASH_ENV", "fake-parent-shell-secret")
	t.Setenv("ENV", "fake-parent-shell-secret")
	child := testScript(t, `test "$KG_TOKEN" = 'fake-secret-XYZ'
test "${BASH_ENV+x}" != x
test "${ENV+x}" != x
test "${KG_UNSELECTED+x}" != x
printf 'isolated'
`)
	var out bytes.Buffer
	code, err := Run(context.Background(), Config{}, []Secret{{Name: "token", Value: secret}}, "", RunOpts{Argv: []string{child}, Stdout: &out})
	if err != nil || code != 0 || out.String() != "isolated" {
		t.Fatalf("child isolation: code=%d err=%v output=%q", code, err, out.String())
	}
	if os.Getenv("KG_TOKEN") != "fake-parent-token" {
		t.Fatal("parent environment changed")
	}
}

func TestRunRedactedOutput(t *testing.T) {
	const secret = "fake-secret-XYZ"
	child := testScript(t, `printf 'out:%s\n' "$KG_TOKEN"
printf 'err:%s\n' "$KG_TOKEN" >&2
printf 'split:fake-'
sleep 0.05
printf 'secret-XYZ\n'
`)
	var stdout, stderr bytes.Buffer
	r := redact.New([]redact.Secret{{Name: "token", Value: secret}})
	out, errout := r.NewWriter(&stdout), r.NewWriter(&stderr)
	code, err := Run(context.Background(), Config{}, []Secret{{Name: "token", Value: secret}}, "", RunOpts{Argv: []string{child}, Stdout: out, Stderr: errout})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if err := out.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := errout.Flush(); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "out:[kg:token]\nsplit:[kg:token]\n" || stderr.String() != "err:[kg:token]\n" {
		t.Fatal("child output was not masked correctly")
	}
}

func TestRunCleansFilesOnExitAndError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		argv    []string
		code    int
		wantErr bool
	}{
		{"success", []string{"/bin/sh", "-c", `test -f "$KG_FILE_CFG"`}, 0, false},
		{"exit", []string{"/bin/sh", "-c", "exit 23"}, 23, false},
		{"empty", nil, -1, true},
		{"start", []string{filepath.Join(t.TempDir(), "missing")}, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := t.TempDir()
			code, err := Run(context.Background(), Config{RunDir: run}, []Secret{{Name: "cfg", Kind: "file", Value: "fake-secret-XYZ"}}, "", RunOpts{Argv: tc.argv})
			if code != tc.code || (err != nil) != tc.wantErr {
				t.Fatalf("code=%d err=%v", code, err)
			}
			assertEmptyRunDir(t, run)
		})
	}
}

func TestNewEnvRollback(t *testing.T) {
	for _, bad := range []Secret{
		{Name: "bad", Kind: "unknown"},
		{Name: "bad", Kind: "file", EnvName: "PATH", Value: "fake-secret-XYZ"},
		{Name: "bad", Kind: "env", EnvName: "ENV"},
	} {
		run := t.TempDir()
		env, err := NewEnv(context.Background(), Config{RunDir: run}, []Secret{{Name: "first", Kind: "file", Value: "fake-secret-first"}, bad}, "")
		if err == nil || env != nil {
			t.Fatal("invalid secret accepted")
		}
		assertEmptyRunDir(t, run)
	}
}

func TestCleanupAllAndVarsCopy(t *testing.T) {
	run := t.TempDir()
	for i := 0; i < 2; i++ {
		env, err := NewEnv(context.Background(), Config{RunDir: run}, []Secret{{Name: "cfg", Kind: "file", Value: "fake-secret-XYZ"}}, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(env.Cleanup)
		vars := env.Vars()
		vars[0] = "BROKEN=value"
		if env.Vars()[0] == vars[0] {
			t.Fatal("Vars aliases internal storage")
		}
	}
	CleanupAll()
	CleanupAll()
	assertEmptyRunDir(t, run)
}

func fakeWalletConfig(t *testing.T, fail bool) Config {
	t.Helper()
	body := `test "$1" = -cp
test "$3" = oracle.security.pki.OracleSecretStoreTextUI
test "$4" = -wrl
dir=$5
action=$6
IFS= read -r first
IFS= read -r second
test "$first" = "$second"
case "$action" in
  -create) test "$#" = 6; umask 077; printf fake-wallet > "$dir/ewallet.p12"; printf fake-wallet > "$dir/cwallet.sso" ;;
  -createCredential) test "$#" = 8; test "$7" = alias; test "$8" = user; test "$first" = fake-secret-XYZ; IFS= read -r walletpw ;;
  *) exit 17 ;;
esac
`
	if fail {
		body += `if test "$action" = -createCredential; then
printf '%s\n%s\n' "$first" "$walletpw" >&2
exit 9
fi
`
	}
	tns := t.TempDir()
	jar := filepath.Join(t.TempDir(), "oraclepki.jar")
	for p, content := range map[string]string{jar: "fake-jar", filepath.Join(tns, "tnsnames.ora"): "alias = fake-descriptor\n"} {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return Config{Java: testScript(t, body), PkiJar: jar, TNSAdmin: tns, RunDir: t.TempDir()}
}

func TestWalletArtifactsWithFakeJava(t *testing.T) {
	cfg := fakeWalletConfig(t, false)
	env, err := NewEnv(context.Background(), cfg, []Secret{{Name: "db", Kind: "oracle-wallet", User: "user", TNSAlias: "alias", Value: "fake-secret-XYZ"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Cleanup)
	vars := env.Vars()
	if len(vars) != 1 || !strings.HasPrefix(vars[0], "TNS_ADMIN=") {
		t.Fatal("wallet environment missing")
	}
	dir := strings.TrimPrefix(vars[0], "TNS_ADMIN=")
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatal("wallet directory not private")
	}
	for _, name := range []string{"ewallet.p12", "cwallet.sso", "tnsnames.ora", "sqlnet.ora", "ojdbc.properties"} {
		p := filepath.Join(dir, name)
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("artifact %s not private: %v", name, err)
		}
		b, err := os.ReadFile(p)
		if err != nil || bytes.Contains(b, []byte("fake-secret-XYZ")) {
			t.Fatalf("unexpected plaintext in %s", name)
		}
		switch name {
		case "tnsnames.ora":
			if string(b) != "alias = fake-descriptor\n" {
				t.Fatal("TNS descriptor changed")
			}
		case "sqlnet.ora":
			if !strings.Contains(string(b), dir) || !strings.Contains(string(b), "SQLNET.WALLET_OVERRIDE = TRUE") {
				t.Fatal("invalid sqlnet configuration")
			}
		case "ojdbc.properties":
			if !strings.Contains(string(b), "oracle.net.wallet_location=") || !strings.Contains(string(b), dir) {
				t.Fatal("invalid JDBC configuration")
			}
		}
	}
	env.Cleanup()
	assertEmptyRunDir(t, cfg.RunDir)
}

func TestWalletFailureScrubsAndCleans(t *testing.T) {
	for _, value := range []string{"fake-secret-XYZ", "fake-secret-XYZ\nextra"} {
		cfg := fakeWalletConfig(t, value == "fake-secret-XYZ")
		var password string
		testWalletPasswordHook = func(p string) { password = p }
		env, err := NewEnv(context.Background(), cfg, []Secret{{Name: "db", Kind: "oracle-wallet", User: "user", TNSAlias: "alias", Value: value}}, "")
		testWalletPasswordHook = nil
		if err == nil || env != nil {
			t.Fatal("wallet failure not returned")
		}
		if strings.Contains(err.Error(), value) || (password != "" && strings.Contains(err.Error(), password)) {
			t.Fatal("wallet error leaked password")
		}
		if value == "fake-secret-XYZ" && (!strings.Contains(err.Error(), "[kg:wallet]") || !strings.Contains(err.Error(), "[kg:db]")) {
			t.Fatal("wallet diagnostic was not scrubbed")
		}
		assertEmptyRunDir(t, cfg.RunDir)
	}
}

func TestCancelKillsTreeAndCleansFiles(t *testing.T) {
	t.Setenv("KG_TEST_HELPER", "1")
	t.Setenv("KG_TEST_MODE", "spawn")
	beat := filepath.Join(t.TempDir(), "beat")
	t.Setenv("KG_TEST_BEAT", beat)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan bool, 1)
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(beat); err == nil {
				ready <- true
				cancel()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		ready <- false
		cancel()
	}()
	run := t.TempDir()
	_, err := Run(ctx, Config{RunDir: run}, []Secret{{Name: "cfg", Kind: "file", Value: "fake-secret-XYZ"}}, "", RunOpts{Argv: helperArgv()})
	if !<-ready {
		t.Fatal("grandchild never started")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error: %v", err)
	}
	a, err := os.ReadFile(beat)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	b, err := os.ReadFile(beat)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("grandchild survived cancellation")
	}
	assertEmptyRunDir(t, run)
}
