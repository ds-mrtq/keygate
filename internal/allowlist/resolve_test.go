package allowlist

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"
)

func TestResolveProgram(t *testing.T) {
	first, second, cwd := t.TempDir(), t.TempDir(), t.TempDir()
	program := fakeProg(t, first, "kg-fixture")
	fakeProg(t, second, "kg-fixture")
	local := fakeProg(t, cwd, "kg-local")
	t.Chdir(cwd)
	t.Setenv("PATH", first+string(os.PathListSeparator)+second)
	if runtime.GOOS == "windows" {
		t.Setenv("PATHEXT", ".EXE")
		t.Setenv("NoDefaultCurrentDirectoryInExePath", "1")
	}

	for _, tc := range []struct{ name, cmd, want string }{
		{"PATH precedence", "kg-fixture", program},
		{"absolute path", program, program},
		{"explicit relative path", "." + string(os.PathSeparator) + filepath.Base(local), local},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveProgram(tc.cmd)
			if err != nil || !filepath.IsAbs(got) || got != tc.want {
				t.Fatalf("ResolveProgram(%q) = %q, %v; want absolute %q", tc.cmd, got, err, tc.want)
			}
		})
	}

	t.Run("reject unresolved and non-executable PATH entries", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(first, "kg-not-executable"), []byte("fixture"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, cmd := range []string{
			"kg-missing",
			filepath.Join(first, "kg-missing"),
			"kg-not-executable",
		} {
			if got, err := ResolveProgram(cmd); err == nil || got != "" {
				t.Errorf("ResolveProgram(%q) = %q, %v; want empty path and error", cmd, got, err)
			}
		}
	})

	t.Run("canonical symlink target", func(t *testing.T) {
		link := filepath.Join(second, "link-"+filepath.Base(program))
		if err := os.Symlink(program, link); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink unavailable: %v", err)
			}
			t.Fatal(err)
		}
		if got, err := ResolveProgram(link); err != nil || got != program {
			t.Fatalf("ResolveProgram(%q) = %q, %v; want target %q", link, got, err, program)
		}
	})
}

func TestResolveKeepsMissingEntriesWithoutMatching(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	program := fakeProg(t, dir, "kg-fixture")
	shadow := fakeProg(t, other, "kg-fixture")
	t.Setenv("PATH", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("PATHEXT", ".EXE")
		t.Setenv("NoDefaultCurrentDirectoryInExePath", "1")
	}
	var entries []Entry
	for _, raw := range []string{"kg-missing", "kg-fixture permitted !exact"} {
		entry, err := ParseEntry(raw)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	resolved := Resolve(entries)
	want := []Resolved{{Entry: entries[0]}, {Entry: entries[1], Path: program}}
	if !reflect.DeepEqual(resolved, want) {
		t.Fatalf("Resolve = %+v; want %+v", resolved, want)
	}

	t.Setenv("PATH", other)
	m, err := Check(resolved, []string{"kg-fixture", "permitted"}, other)
	if err != nil || m.Path != program || !slices.Equal(m.Argv, []string{program, "permitted"}) {
		t.Fatalf("Check after PATH change = %+v, %v; want argv bound to %q", m, err, program)
	}
	for _, argv := range [][]string{{"kg-missing"}, {shadow, "permitted"}, {"kg-fixture", "other"}} {
		if m, err := Check(resolved, argv, other); m != nil || !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Check(%q) = %+v, %v; want ErrNotAllowed", argv, m, err)
		}
	}
}

func TestCheckRejectsReplacedPinnedProgram(t *testing.T) {
	dir := t.TempDir()
	program := fakeProg(t, dir, "kg-fixture")
	hash, err := FileHash(program)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ParseEntry(`"` + program + `" ` + hash + " !exact")
	if err != nil {
		t.Fatal(err)
	}
	resolved := Resolve([]Entry{entry})
	argv := []string{program}
	m, err := Check(resolved, argv, dir)
	if err != nil || !entry.HasContentPin() || m.Path != program ||
		!slices.Equal(m.Argv, argv) || len(m.Pins) != 1 ||
		m.Pins[0].Path != program || m.Pins[0].Hash != hash {
		t.Fatalf("Check for original program = %+v, %v; want executable path and program pin", m, err)
	}
	lock, err := m.LockPins()
	if err != nil {
		t.Fatalf("LockPins for original program: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(program, program+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte("replacement fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := Check(resolved, argv, dir); got != nil || !errors.Is(err, ErrBlocked) {
		t.Errorf("Check for replacement = %+v, %v; want ErrBlocked", got, err)
	}
	lock, err = m.LockPins()
	if lock != nil {
		lock.Close()
	}
	if lock != nil || !errors.Is(err, ErrBlocked) {
		t.Errorf("LockPins on prior match after replacement = %v, %v; want ErrBlocked", lock, err)
	}
}
