package execwrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("KG_TEST_HELPER") != "1" {
		return
	}
	switch os.Getenv("KG_TEST_MODE") {
	case "sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "beat":
		for i := 0; i < 600; i++ {
			os.WriteFile(os.Getenv("KG_TEST_BEAT"), []byte(fmt.Sprint(i)), 0o600)
			time.Sleep(50 * time.Millisecond)
		}
		os.Exit(0)
	case "spawn":
		c := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
		c.Env = append(os.Environ(), "KG_TEST_MODE=beat")
		c.Start()
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	for _, k := range strings.Split(os.Getenv("KG_TEST_PRINT"), ",") {
		v := os.Getenv(k)
		if strings.HasPrefix(k, "KG_FILE") {
			b, err := os.ReadFile(v)
			if err != nil {
				os.Stdout.WriteString("READERR\n")
				os.Exit(3)
			}
			v = string(b)
		}
		os.Stdout.WriteString(k + "=" + v + "\n")
	}
	os.Exit(7)
}

func helperArgv() []string {
	return []string{os.Args[0], "-test.run=TestHelperProcess"}
}

func TestEnvAndFile(t *testing.T) {
	secrets := []Secret{
		{Name: "ebs/test/token", Value: "tok-123456", Kind: "env"},
		{Name: "cfg", Value: "line1\nline2", Kind: "file", FileExt: "json"},
		{Name: "named", Value: "nv", Kind: "env", EnvName: "MY_NAMED"},
	}
	t.Setenv("KG_TEST_HELPER", "1")
	t.Setenv("KG_TEST_PRINT", "KG_HT_TEST_TOKEN,KG_FILE_CFG,MY_NAMED")
	var out bytes.Buffer
	env, err := NewEnv(context.Background(), Config{}, secrets, "")
	if err != nil {
		t.Fatal(err)
	}
	var filePath string
	for _, v := range env.Vars() {
		if strings.HasPrefix(v, "KG_FILE_CFG=") {
			filePath = strings.TrimPrefix(v, "KG_FILE_CFG=")
		}
	}
	if !strings.HasSuffix(filePath, ".json") {
		t.Fatalf("file path %q", filePath)
	}
	if st, err := os.Stat(filePath); err != nil || (os.PathSeparator == '/' && st.Mode().Perm() != 0o600) {
		t.Fatalf("file %v %v", st, err)
	}
	code, err := env.Run(context.Background(), RunOpts{Argv: helperArgv(), Stdout: &out, Stderr: &out})
	if err != nil || code != 7 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	got := out.String()
	for _, w := range []string{"KG_HT_TEST_TOKEN=tok-123456", "KG_FILE_CFG=line1\nline2", "MY_NAMED=nv"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in %q", w, got)
		}
	}
	env.Cleanup()
	env.Cleanup()
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatal("temp file not removed")
	}
	if _, err := os.Stat(filepath.Dir(filePath)); !os.IsNotExist(err) {
		t.Fatal("temp dir not removed")
	}
}

func TestAsOverrideAndErrors(t *testing.T) {
	env, err := NewEnv(context.Background(), Config{}, []Secret{{Name: "a", Value: "v", Kind: "env"}}, "file")
	if err != nil {
		t.Fatal(err)
	}
	env.Cleanup()
	if _, err := NewEnv(context.Background(), Config{}, []Secret{{Name: "a", Value: "v"}}, "bogus"); err == nil {
		t.Fatal("bad --as must fail")
	}
	if _, err := NewEnv(context.Background(), Config{}, []Secret{{Name: "a", Value: "v", Kind: "oracle-wallet"}}, ""); err == nil {
		t.Fatal("wallet without user/alias must fail")
	}
}

func TestTemplate(t *testing.T) {
	tmpl := "a=${secret:x/1} b=${secret:y} c=${secret:x/1}"
	names := TemplateNames(tmpl)
	if len(names) != 2 || names[0] != "x/1" || names[1] != "y" {
		t.Fatalf("%v", names)
	}
	got, err := ResolveTemplate(tmpl, map[string]string{"x/1": "${secret:y}", "y": "Y"})
	if err != nil || got != "a=${secret:y} b=Y c=${secret:y}" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := ResolveTemplate(tmpl, map[string]string{"y": "Y"}); err == nil || strings.Contains(err.Error(), "Y") && !strings.Contains(err.Error(), "x/1") {
		t.Fatalf("missing must error naming the secret: %v", err)
	}
}

func TestRandomPassword(t *testing.T) {
	a, _ := RandomPassword(24)
	b, _ := RandomPassword(24)
	if len(a) != 24 || a == b {
		t.Fatal(a, b)
	}
}

func TestWallet(t *testing.T) {
	java, err := FindJava(Config{})
	if err != nil {
		t.Skip("không có JDK >= 11:", err)
	}
	jar, err := FindPkiJar(Config{})
	if err != nil {
		t.Skip("không có oraclepki.jar:", err)
	}
	tns := t.TempDir()
	tnsText := "ALIAS1 = (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=x)))\n"
	os.WriteFile(filepath.Join(tns, "tnsnames.ora"), []byte(tnsText), 0o600)
	cfg := Config{Java: java, PkiJar: jar, TNSAdmin: tns}
	var wpw string
	testWalletPasswordHook = func(p string) { wpw = p }
	defer func() { testWalletPasswordHook = nil }()
	env, err := NewEnv(context.Background(), cfg, []Secret{
		{Name: "ebs/test/db", Value: "S3cret-Pass!9", Kind: "oracle-wallet", User: "scott", TNSAlias: "alias1"},
		{Name: "ebs/test/db2", Value: "An0ther-Pass#7", Kind: "oracle-wallet", User: "hr", TNSAlias: "alias2"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	var wdir string
	for _, v := range env.Vars() {
		if strings.HasPrefix(v, "TNS_ADMIN=") {
			wdir = strings.TrimPrefix(v, "TNS_ADMIN=")
		}
	}
	if wdir == "" {
		t.Fatal("TNS_ADMIN not set")
	}
	cmd := exec.Command(java, "-cp", jar, pkiClass, "-wrl", wdir, "-listCredential")
	cmd.Stdin = strings.NewReader(wpw + "\n")
	lout, lerr := cmd.CombinedOutput()
	if lerr != nil {
		t.Fatalf("%v: %s", lerr, lout)
	}
	for _, w := range []string{"alias1 scott", "alias2 hr"} {
		if !strings.Contains(string(lout), w) {
			t.Errorf("credential %q not listed: %s", w, lout)
		}
	}
	if strings.Contains(string(lout), "Pass") {
		t.Error("password printed")
	}
	for _, f := range []string{"ewallet.p12", "cwallet.sso", "tnsnames.ora", "sqlnet.ora"} {
		if _, err := os.Stat(filepath.Join(wdir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	sq, _ := os.ReadFile(filepath.Join(wdir, "sqlnet.ora"))
	if !strings.Contains(string(sq), "WALLET_LOCATION") || !strings.Contains(string(sq), "SQLNET.WALLET_OVERRIDE = TRUE") {
		t.Errorf("sqlnet.ora: %s", sq)
	}
	if tb, _ := os.ReadFile(filepath.Join(wdir, "tnsnames.ora")); string(tb) != tnsText {
		t.Error("tnsnames.ora not copied")
	}
	env.Cleanup()
	if _, err := os.Stat(wdir); !os.IsNotExist(err) {
		t.Fatal("wallet dir not removed")
	}
}

func TestRunDirSweepAndShred(t *testing.T) {
	run := filepath.Join(t.TempDir(), "run")
	env, err := NewEnv(context.Background(), Config{RunDir: run}, []Secret{{Name: "f", Value: "file-secret-1234", Kind: "file"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	var p string
	for _, v := range env.Vars() {
		if strings.HasPrefix(v, "KG_FILE_F=") {
			p = strings.TrimPrefix(v, "KG_FILE_F=")
		}
	}
	if !strings.HasPrefix(p, run) {
		t.Fatalf("temp file %q not under run dir %q", p, run)
	}
	if err := Sweep(run); err != nil { // simulates broker restart after a crash
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(run); len(ents) != 0 {
		t.Fatalf("sweep left %d entries", len(ents))
	}
	env.Cleanup()
}

func TestEnvNameValidation(t *testing.T) {
	for _, bad := range []string{"JAVA_TOOL_OPTIONS", "PATH", "LD_PRELOAD", "PYTHONPATH", "X=Y", "1ABC", "A B"} {
		if _, err := NewEnv(context.Background(), Config{}, []Secret{{Name: "a", Value: "v", Kind: "env", EnvName: bad}}, ""); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	env, _ := NewEnv(context.Background(), Config{}, nil, "")
	defer env.Cleanup()
	if _, err := env.AddFile(Config{}, "JAVA_TOOL_OPTIONS=-javaagent:x", []byte("x"), ""); err == nil {
		t.Fatal("into must be validated")
	}
}

func TestMaxRuntimeKillsTree(t *testing.T) {
	t.Setenv("KG_TEST_HELPER", "1")
	t.Setenv("KG_TEST_MODE", "spawn")
	beat := filepath.Join(t.TempDir(), "beat")
	t.Setenv("KG_TEST_BEAT", beat)
	env, _ := NewEnv(context.Background(), Config{}, nil, "")
	defer env.Cleanup()
	start := time.Now()
	var out bytes.Buffer
	code, err := env.Run(context.Background(), RunOpts{Argv: helperArgv(), Stdout: &out, Stderr: &out, MaxRuntime: 1500 * time.Millisecond})
	if !errors.Is(err, ErrMaxRuntime) {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatal("Run did not return promptly after kill")
	}
	a, _ := os.ReadFile(beat)
	time.Sleep(600 * time.Millisecond)
	b, _ := os.ReadFile(beat)
	if string(a) != string(b) {
		t.Fatalf("grandchild still running (beat %s -> %s)", a, b)
	}
}
