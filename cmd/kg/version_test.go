package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func runVersion(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	a := &app{home: t.TempDir(), out: &out, errw: &errb}
	code := a.run(args)
	return code, out.String(), errb.String()
}

func TestVersionCommand(t *testing.T) {
	oldVersion, oldCommit := version, commit
	t.Cleanup(func() { version, commit = oldVersion, oldCommit })
	version, commit = "v1.2.3", "0123456789abcdef0123"

	want := "kg v1.2.3 (commit 0123456789ab, " + runtime.GOOS + "/" + runtime.GOARCH + ")\n"
	for _, arg := range []string{"version", "--version"} {
		code, out, errs := runVersion(t, arg)
		if code != 0 || out != want || errs != "" {
			t.Fatalf("kg %s = %d %q %q, want 0 %q", arg, code, out, errs, want)
		}
	}
	if code, out, _ := runVersion(t, "version", "extra"); code != 2 || out != "" {
		t.Fatalf("kg version extra = %d %q, want usage error", code, out)
	}
}

func TestVersionDefaultsToDev(t *testing.T) {
	oldVersion, oldCommit := version, commit
	t.Cleanup(func() { version, commit = oldVersion, oldCommit })
	version, commit = "dev", ""

	_, out, _ := runVersion(t, "version")
	if !strings.HasPrefix(out, "kg dev (commit ") || !strings.HasSuffix(out, ", "+runtime.GOOS+"/"+runtime.GOARCH+")\n") {
		t.Fatalf("plain build version = %q", out)
	}
}
