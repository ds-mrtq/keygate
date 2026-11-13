package allowlist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLockPinsBlocksWritesWindows(t *testing.T) {
	d := t.TempDir()
	py := fakeProg(t, d, "python")
	script := filepath.Join(d, "job.py")
	os.WriteFile(script, []byte("print(1)"), 0o644)
	h, _ := FileHash(script)
	es := mkEntries(t, map[string]string{"python": py}, "python path:"+filepath.ToSlash(script)+" "+h)
	m, err := Check(es, []string{"python", script}, d)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(d, "other.py")
	os.WriteFile(other, []byte("evil"), 0o644)
	lk, err := m.LockPins()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("evil"), 0o644); err == nil {
		t.Error("write must fail while locked")
	}
	if f, err := os.OpenFile(script, os.O_APPEND|os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Error("append must fail while locked")
	}
	if err := os.Remove(script); err == nil {
		t.Error("remove must fail while locked")
	}
	if err := os.Rename(other, script); err == nil {
		t.Error("rename onto the file must fail while locked")
	}
	if err := os.Rename(script, filepath.Join(d, "moved.py")); err == nil {
		t.Error("rename away must fail while locked")
	}
	if b, err := os.ReadFile(script); err != nil || string(b) != "print(1)" {
		t.Errorf("readers must still work: %q %v", b, err)
	}
	if err := lk.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("ok"), 0o644); err != nil {
		t.Errorf("write after Close: %v", err)
	}
	if err := os.Rename(other, script); err != nil {
		t.Errorf("rename after Close: %v", err)
	}
	if err := os.Remove(script); err != nil {
		t.Errorf("remove after Close: %v", err)
	}
}
