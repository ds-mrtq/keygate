package allowlist

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func mkEntries(t *testing.T, defs map[string]string, lines ...string) []Resolved {
	t.Helper()
	var es []Entry
	for _, l := range lines {
		e, err := ParseEntry(l)
		if err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		es = append(es, e)
	}
	var out []Resolved
	for _, e := range es {
		out = append(out, Resolved{Entry: e, Path: defs[BaseName(e.Cmd)]})
	}
	return out
}

// fakeProg creates an empty file standing in for a program and returns its canonical path.
func fakeProg(t *testing.T, dir, name string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	return canon(p)
}

func TestCheckPathsAndNames(t *testing.T) {
	d := t.TempDir()
	sql := fakeProg(t, d, "sql")
	py := fakeProg(t, d, "python")
	defs := map[string]string{"sql": sql, "python": py}
	script := filepath.ToSlash(filepath.Join(d, "scripts")) // allowed script dir
	os.MkdirAll(script, 0o755)
	os.WriteFile(filepath.Join(script, "ok.py"), []byte("x"), 0o644)
	es := mkEntries(t, defs, "sql /@HTTEST @*.sql", `python path:`+script+`/**/*.py`)

	// bare name ok, program replaced by the resolved path, restrict injected
	m, err := Check(es, []string{"SQL", "/@HTTEST", "@a.sql"}, d)
	if err != nil || m.Argv[0] != sql || m.Argv[1] != "-R" || m.Argv[2] != "4" || m.Argv[3] != "/@HTTEST" {
		t.Fatalf("sql: %+v %v", m, err)
	}
	// exact resolved path ok
	if _, err := Check(es, []string{sql, "/@HTTEST", "@a.sql"}, d); err != nil {
		t.Fatalf("resolved path: %v", err)
	}
	// any other path => deny (C1)
	if _, err := Check(es, []string{filepath.Join(d, "evil", "sql"), "/@HTTEST", "@a.sql"}, d); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("other path: %v", err)
	}
	if _, err := Check(es, []string{"." + string(filepath.Separator) + "sql", "/@HTTEST", "@a.sql"}, d); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("relative path: %v", err)
	}
	// restrict level cannot be overridden
	if _, err := Check(es, []string{"sql", "/@HTTEST", "@a.sql", "-R", "0"}, d); err == nil {
		t.Fatal("-R override must be refused")
	}
	// '*' stops at separators, '..' refused in globbed args
	for _, bad := range []string{"@C:/tmp/x.sql", "@../x.sql", "@sub/a.sql"} {
		if _, err := Check(es, []string{"sql", "/@HTTEST", bad}, d); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := Check(es, []string{"sql", "/@OTHER", "@a.sql"}, d); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("wrong alias: %v", err)
	}
	// extra arguments beyond the patterns are allowed unless !exact
	if _, err := Check(es, []string{"sql", "/@HTTEST", "@a.sql", "more"}, d); err != nil {
		t.Fatalf("trailing: %v", err)
	}

	// interpreter: script path pattern, no leading options, no ..
	good := filepath.Join(script, "ok.py")
	if _, err := Check(es, []string{"python", good, "--flag"}, d); err != nil {
		t.Fatalf("script: %v", err)
	}
	for _, a := range [][]string{
		{"python", "-c", "print(1)"},
		{"python", "-Bc", "x"},
		{"python", "-m", "http.server"},
		{"python", filepath.Join(script, "..", "..", "evil.py")},
		{"python", filepath.Join(d, "other", "x.py")},
		{"python"},
	} {
		if _, err := Check(es, a, d); err == nil {
			t.Errorf("%v must be refused", a)
		}
	}
	// relative script resolved against dir
	if _, err := Check(es, []string{"python", "scripts/ok.py"}, d); err != nil {
		t.Fatalf("relative script in allowed dir: %v", err)
	}
}

func TestExactAndQuotes(t *testing.T) {
	d := t.TempDir()
	p := fakeProg(t, d, "tool")
	es := mkEntries(t, map[string]string{"tool": p}, `tool "a b" run !exact`)
	if _, err := Check(es, []string{"tool", "a b", "run"}, d); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(es, []string{"tool", "a b", "run", "extra"}, d); err == nil {
		t.Fatal("exact must refuse trailing args")
	}
}

func TestShellsAlwaysBlocked(t *testing.T) {
	for _, l := range []string{"cmd /c", "cmd path:C:/x.bat", "env a", "xargs a", "busybox sh", "fish path:/a.sh", "bash x", "bash", "bash path:/a/*.sh", "powershell -File x"} {
		if _, err := ParseEntry(l); err == nil {
			t.Errorf("entry %q must be rejected", l)
		}
	}
	for _, a := range [][]string{{"fish", "-c", "x"}, {`C:\Windows\System32\cmd.exe`, "/c"}, {"env"}, {"nu"}} {
		if _, err := Check(nil, a, "."); !errors.Is(err, ErrBlocked) {
			t.Errorf("%v: %v", a, err)
		}
	}
	// a program that RESOLVES to a shell is blocked even when it is listed under another name
	d := t.TempDir()
	cmd := fakeProg(t, d, "cmd")
	es := []Resolved{{Entry: Entry{Raw: "tool x", Cmd: "tool", Args: []string{"x"}}, Path: cmd}}
	if _, err := Check(es, []string{"tool", "x"}, d); !errors.Is(err, ErrBlocked) {
		t.Fatalf("resolved shell: %v", err)
	}
}

func TestScriptHostsNeedPatterns(t *testing.T) {
	for _, l := range []string{"sql", "sqlplus", "java", "make", "git", "ssh", "find", "python", "node"} {
		if _, err := ParseEntry(l); err == nil {
			t.Errorf("%q without patterns must be rejected", l)
		}
	}
	if _, err := ParseEntry("curl"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEntry("python path:relative/*.py"); err == nil {
		t.Fatal("relative path: pattern must be rejected")
	}
	if _, err := ParseEntry("tool relative/prog"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEntry("rel/prog"); err == nil {
		t.Fatal("relative program path must be rejected")
	}
}

func TestGlobPath(t *testing.T) {
	yes := [][2]string{{"*.py", "a.py"}, {"a/*/c", "a/b/c"}, {"a/**/c", "a/b/x/c"}, {"**", "a/b"}, {"/@X", "/@X"}, {`D:\a\*.py`, "D:/a/b.py"}}
	no := [][2]string{{"*.py", "a/b.py"}, {"a/*/c", "a/b/x/c"}, {"?", "/"}, {"a?c", "abbc"}}
	for _, c := range yes {
		if !GlobPath(c[0], c[1]) {
			t.Errorf("%q should match %q", c[0], c[1])
		}
	}
	for _, c := range no {
		if GlobPath(c[0], c[1]) {
			t.Errorf("%q should not match %q", c[0], c[1])
		}
	}
}

func TestGlobNames(t *testing.T) {
	if !Glob("*/prod/*", "a/prod/b") || Glob("a?c", "ac") || !Glob("x*", "x") {
		t.Fatal("glob")
	}
}

func TestPinnedShell(t *testing.T) {
	d := t.TempDir()
	sh := fakeProg(t, d, "bash")
	ps := fakeProg(t, d, "pwsh")
	script := filepath.Join(d, "run.sh")
	os.WriteFile(script, []byte("echo hi"), 0o644)
	other := filepath.Join(d, "other.sh")
	os.WriteFile(other, []byte("echo hi"), 0o644)
	ps1 := filepath.Join(d, "x.ps1")
	os.WriteFile(ps1, []byte("x"), 0o644)
	sp, pp := filepath.ToSlash(script), filepath.ToSlash(ps1)
	es := mkEntries(t, map[string]string{"bash": sh, "pwsh": ps}, "bash path:"+sp+" !exact", "pwsh path:"+pp+" a*")

	m, err := Check(es, []string{"bash", script}, d)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{sh, "--noprofile", "--norc", canon(script)}
	if strings.Join(m.Argv, "|") != strings.Join(want, "|") {
		t.Fatalf("argv %v", m.Argv)
	}
	if _, err := Check(es, []string{"bash", script, "extra"}, d); err == nil {
		t.Fatal("!exact must refuse extra args")
	}
	for _, a := range [][]string{
		{"bash", other}, {"bash", "-c", "id"}, {"bash", "-x", script}, {"bash"}, {"bash", "-s", script},
		{"bash", "--rcfile", script},
	} {
		if _, err := Check(es, a, d); err == nil {
			t.Errorf("%v must be refused", a)
		}
	}
	m, err = Check(es, []string{"pwsh", ps1, "abc"}, d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.Argv[1:], "|") != "-NoProfile|-NonInteractive|-ExecutionPolicy|Bypass|-File|"+canon(ps1)+"|abc" {
		t.Fatalf("ps argv %v", m.Argv)
	}
	if _, err := Check(es, []string{"pwsh", ps1, "zzz"}, d); err == nil {
		t.Fatal("extra pattern must apply")
	}
	// symlinked pinned script is refused
	link := filepath.Join(d, "link.sh")
	if os.Symlink(script, link) == nil {
		es2 := mkEntries(t, map[string]string{"bash": sh}, "bash path:"+filepath.ToSlash(link))
		if _, err := Check(es2, []string{"bash", link}, d); err == nil {
			t.Fatal("symlink script must be refused")
		}
	}
}

func TestHashPinnedScript(t *testing.T) {
	d := t.TempDir()
	py := fakeProg(t, d, "python")
	script := filepath.Join(d, "job.py")
	os.WriteFile(script, []byte("print(1)"), 0o644)
	h, err := FileHash(script)
	if err != nil {
		t.Fatal(err)
	}
	sp := filepath.ToSlash(script)
	es := mkEntries(t, map[string]string{"python": py}, "python path:"+sp+" "+h)
	if !es[0].HasContentPin() {
		t.Fatal("pin not recorded")
	}
	if _, err := Check(es, []string{"python", script}, d); err != nil {
		t.Fatalf("match: %v", err)
	}
	os.WriteFile(script, []byte("print(2)"), 0o644)
	_, err = Check(es, []string{"python", script}, d)
	if !errors.Is(err, ErrBlocked) || !strings.Contains(err.Error(), "sha256:") || strings.Contains(err.Error(), "print(2)") {
		t.Fatalf("mismatch must be denied showing the hash only: %v", err)
	}
	for _, bad := range []string{
		"python path:" + sp + " sha256:xyz",
		"python path:" + d + "/*.py " + h,
		"python " + h,
	} {
		if _, err := ParseEntry(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	// program pin
	ph, _ := FileHash(py)
	es2 := mkEntries(t, map[string]string{"tool": py}, "\""+filepath.ToSlash(py)+"\" "+ph+" x")
	_ = es2
}
