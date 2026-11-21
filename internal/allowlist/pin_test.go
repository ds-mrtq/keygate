package allowlist

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPinRawAddsAndRefreshesScriptPins(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "café job.py")
	config := filepath.Join(dir, "config file")
	glob := filepath.Join(dir, "*.txt")
	hashes := make(map[string]string)
	for path, content := range map[string]string{script: "script fixture", config: "config fixture"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		h, err := FileHash(path)
		if err != nil {
			t.Fatal(err)
		}
		hashes[path] = h
	}
	start := `  Python3.12.EXE   "path:` + script + `"`
	middle := `  literal   "@path:` + config + `"  `
	end := `  "path:` + glob + `" !exact  `
	raw := start + middle + "sha256:" + strings.Repeat("0", 64) + end
	want := start + " " + hashes[script] + middle + hashes[config] + end
	calls := map[string]int{}
	hash := func(path string) (string, error) {
		calls[path]++
		return FileHash(path)
	}
	for _, input := range []string{raw, want} {
		clear(calls)
		got, err := PinRaw(input, hash)
		if err != nil || got != want {
			t.Fatalf("PinRaw(%q) = %q, %v; want %q", input, got, err, want)
		}
		if !reflect.DeepEqual(calls, map[string]int{script: 1, config: 1}) {
			t.Fatalf("hashed paths = %v; want only the two exact paths once each", calls)
		}
	}
	entry, err := ParseEntry(want)
	if err != nil {
		t.Fatal(err)
	}
	if entry.UnpinnedScript() || !entry.Exact || !reflect.DeepEqual(entry.Pins, map[int]string{0: hashes[script], 2: hashes[config]}) {
		t.Fatalf("rewritten entry = %+v; want exact policy with pins for script and config", entry)
	}
}

func TestPinRawLeavesOrdinaryCommandsAndInvalidInputUnchanged(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		wantErr bool
	}{
		{`tool "path:/fake job.py"`, false},
		{`python "path:/fake job.py`, true},
		{"   ", true},
	} {
		got, err := PinRaw(tc.raw, func(path string) (string, error) {
			t.Fatalf("unexpected hash callback for %q", path)
			return "", nil
		})
		if got != tc.raw || (err != nil) != tc.wantErr {
			t.Errorf("PinRaw(%q) = %q, %v; want unchanged input (error: %v)", tc.raw, got, err, tc.wantErr)
		}
	}
}

func TestPinRawHashFailureReturnsOriginalItem(t *testing.T) {
	raw := "bash path:/fake-script.sh path:/fake-config"
	fail := errors.New("fixture hash failure")
	var failedPath string
	calls := 0
	got, err := PinRaw(raw, func(path string) (string, error) {
		calls++
		if calls == 2 {
			failedPath = path
			return "", fail
		}
		return "sha256:" + strings.Repeat("1", 64), nil
	})
	if got != raw || !errors.Is(err, fail) || !strings.Contains(err.Error(), failedPath) {
		t.Fatalf("PinRaw(%q) = %q, %v; want original item and wrapped error for %q", raw, got, err, failedPath)
	}
}

func TestUnpinnedScript(t *testing.T) {
	hash := " sha256:" + strings.Repeat("1", 64)
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"interpreter script", "python path:/fixture.py", true},
		{"Windows-style interpreter name", "PyThOn3.12W.ExE @path:/fixture.py", true},
		{"shell script", "bash path:/fixture.sh", true},
		{"glob pattern", "python path:/scripts/*.py", true},
		{"later argument pin", "node path:/fixture.js path:/config" + hash, true},
		{"script pin", "python @path:/fixture.py" + hash, false},
		{"shell script pin", "pwsh path:/fixture.ps1" + hash, false},
		{"ordinary command", "tool path:/fixture.py", false},
		{"not a path pattern", "python fixture.py", false},
		{"path pattern is not first", "python fixture.py path:/config", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := ParseEntry(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := entry.UnpinnedScript(); got != tc.want {
				t.Errorf("UnpinnedScript(%q) = %v; want %v", tc.raw, got, tc.want)
			}
		})
	}
}
