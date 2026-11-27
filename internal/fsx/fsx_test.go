package fsx

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestWriteAtomicReplacesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "device.key")
	write := func(want string) os.FileInfo {
		t.Helper()
		if err := WriteAtomic(path, []byte(want)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatal("key file did not contain exactly the requested bytes")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("key file permissions = %04o, want 0600", info.Mode().Perm())
		}
		return info
	}
	before := write("fake-original-key-blob")
	after := write("fake-new-key")
	if runtime.GOOS != "windows" && os.SameFile(before, after) {
		t.Fatal("key file was rewritten in place instead of replaced")
	}
}

func TestWriteAtomicCleansUpFailedReplacement(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "device.key")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, "keep")
	if err := os.WriteFile(marker, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(path, []byte("fake-key-blob")); err == nil {
		t.Fatal("unexpectedly replaced a directory with a key file")
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "untouched" {
		t.Fatalf("failed replacement changed the destination directory: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatal("failed replacement left a temporary file behind")
	}
}

func TestAppendLinesPreservesLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log", "test.kgl")
	want := [][]byte{[]byte(`{"seq":1}`), []byte(`{"seq":2}`), []byte(`{"seq":3}`)}
	if err := AppendLines(path, want[:2]...); err != nil {
		t.Fatal(err)
	}
	if err := AppendLines(path, want[2]); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLines(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(got, want, bytes.Equal) {
		t.Fatalf("log records = %q, want %q", got, want)
	}
	got, repaired, err := ReadLinesRepair(path)
	if err != nil {
		t.Fatal(err)
	}
	if repaired || !slices.EqualFunc(got, want, bytes.Equal) {
		t.Fatalf("reopening log yielded %q (repaired=%t), want all records without repair", got, repaired)
	}
}

func TestLogIORejectsDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.kgl")
	if got, err := ReadLines(path); err != nil || len(got) != 0 {
		t.Fatalf("missing log = %q, %v; want empty without error", got, err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadLines(path); err == nil || len(got) != 0 {
		t.Fatalf("log path is a directory: got %q, %v; want a read error without records", got, err)
	}
	if err := AppendLines(path, []byte(`{"seq":1}`)); err == nil {
		t.Fatal("appending to a directory should return an error")
	}
}

func TestLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock")
	un, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	un2, err := Lock(p) // same process: re-entrant
	if err != nil {
		t.Fatal(err)
	}
	un2()
	un2() // Repeating a release must not take away the first caller's lock.
	if _, err := os.Stat(p); err != nil {
		t.Fatal("lock released too early")
	}
	un()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("lock file left behind")
	}
	// stale: pid that cannot be alive
	os.WriteFile(p, []byte("2147483646\n"), 0o600)
	un, err = Lock(p)
	if err != nil {
		t.Fatalf("stale lock not taken over: %v", err)
	}
	un()
	// live foreign owner: our parent process
	os.WriteFile(p, []byte(itoa(os.Getppid())+"\n"), 0o600)
	if _, err := Lock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}

func TestLockAcquisitionAfterFailure(t *testing.T) {
	for _, scenario := range []string{"missing parent", "malformed PID"} {
		t.Run(scenario, func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), "vault")
			path := filepath.Join(parent, "lock")
			if scenario == "missing parent" {
				un, err := Lock(path)
				if un != nil {
					defer un()
				}
				if un != nil || !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("acquiring without a parent: got release=%t, err=%v; want only a missing-path error", un != nil, err)
				}
			}
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if scenario == "malformed PID" {
				if err := os.WriteFile(path, []byte("not-a-pid\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			un, err := Lock(path)
			if err != nil || un == nil {
				t.Fatalf("acquiring a usable lock path: got release=%t, err=%v", un != nil, err)
			}
			t.Cleanup(un)
			data, err := os.ReadFile(path)
			if err != nil || string(data) != itoa(os.Getpid())+"\n" {
				t.Fatalf("lock did not record the current process: got %q, err=%v", data, err)
			}
			un()
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("lock was not removed on release: %v", err)
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestReadLinesRepair(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.kgl")
	os.WriteFile(p, []byte("one\ntwo\npartial"), 0o600)
	lines, repaired, err := ReadLinesRepair(p)
	if err != nil || !repaired || len(lines) != 2 {
		t.Fatalf("%v %v %d", err, repaired, len(lines))
	}
	if b, _ := os.ReadFile(p); string(b) != "one\ntwo\n" {
		t.Fatalf("file %q", b)
	}
}
