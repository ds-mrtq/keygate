package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keygate/internal/allowlist"
)

func TestPolicyPinDryRunAndWrite(t *testing.T) {
	d := t.TempDir()
	script := filepath.ToSlash(filepath.Join(d, "job.py"))
	if err := os.WriteFile(script, []byte("print(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := allowlist.FileHash(script)
	if err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(d, "policy.yaml")
	src := "grants:\n  x/y:\n    allow_commands: [\"python path:" + script + "\", curl]\n"
	os.WriteFile(pol, []byte(src), 0o600)

	var out, errw bytes.Buffer
	a := &app{out: &out, errw: &errw}
	if err := a.cmdPolicy([]string{"pin", "--dry-run", pol}); err != nil {
		t.Fatal(err, errw.String())
	}
	if !strings.Contains(out.String(), "- python path:"+script+"\n+ python path:"+script+" "+h+"\n") || !strings.Contains(out.String(), "dry-run") {
		t.Fatalf("dry-run output: %q", out.String())
	}
	if b, _ := os.ReadFile(pol); string(b) != src {
		t.Fatalf("dry-run must not modify the file: %q", b)
	}
	out.Reset()
	if err := a.cmdPolicy([]string{"pin", pol}); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(src, script+"\"", script+" "+h+"\"", 1)
	if b, _ := os.ReadFile(pol); string(b) != want {
		t.Fatalf("written file: %q want %q", b, want)
	}
	if err := a.cmdPolicy([]string{"pin"}); err == nil {
		t.Fatal("missing file argument must be refused")
	}
}
