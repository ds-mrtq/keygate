package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keygate/internal/allowlist"
)

func TestHashCLIPrintsOnlyUsablePolicyPins(t *testing.T) {
	dir := t.TempDir()
	a := newTestApp(t, dir)
	path := filepath.Join(dir, "test input.bin")
	for _, data := range []string{"synthetic\x00input\r\n", "synthetic\x00input\n"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("sha256:%x\n", sha256.Sum256([]byte(data)))
		if out := a.do(t, "hash", path); out != want || a.errb.Len() != 0 {
			t.Fatalf("hash should emit exactly %q: stdout=%q stderr=%q", want, out, a.errb.String())
		}
	}
	if err := os.Truncate(path, (16<<20)+1); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", []string{"hash"}, "kg hash <file>"},
		{"directory", []string{"hash", dir}, "không phải file thường"},
		{"oversized", []string{"hash", path}, "file lớn hơn 16 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a.out.Reset()
			a.errb.Reset()
			if code := a.run(tc.args); code != 1 || a.out.Len() != 0 || !strings.Contains(a.errb.String(), tc.want) {
				t.Fatalf("expected exit 1 with no pin and error %q: exit=%d stdout=%q stderr=%q", tc.want, code, a.out.String(), a.errb.String())
			}
		})
	}
}

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
