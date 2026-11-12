package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
