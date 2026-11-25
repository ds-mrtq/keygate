package main

import (
	"bytes"
	"strings"
	"testing"
)

// kgw.exe has no console, so a double-click without arguments must start something visible
// instead of printing usage nobody sees.
func TestNoArgsRunsDefaultCommand(t *testing.T) {
	var out, errb bytes.Buffer
	a := &app{home: t.TempDir(), out: &out, errw: &errb, defaultCmd: func() string { return "version" }}
	if code := a.run(nil); code != 0 || !strings.HasPrefix(out.String(), "kg ") {
		t.Fatalf("run(nil) with default = %d %q %q, want the default command's output", code, out.String(), errb.String())
	}
}

func TestNoArgsWithConsolePrintsUsage(t *testing.T) {
	for _, def := range []func() string{nil, func() string { return "" }} {
		var out, errb bytes.Buffer
		a := &app{home: t.TempDir(), out: &out, errw: &errb, defaultCmd: def}
		if code := a.run(nil); code != 2 || !strings.Contains(errb.String(), "Dùng: kg") {
			t.Fatalf("run(nil) = %d %q, want usage and 2", code, errb.String())
		}
	}
}
