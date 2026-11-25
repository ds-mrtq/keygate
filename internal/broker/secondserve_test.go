package broker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A second broker on the same KG_HOME (kgw.exe double-clicked again) must refuse before it sweeps
// the run directory, or the running broker's `kg run` children lose their input files.
func TestSecondServeKeepsRunningBrokersRunDir(t *testing.T) {
	f := newFixture(t, 0, 0)
	in := filepath.Join(RunDir(f.home), "live-run", "input")
	if err := os.MkdirAll(filepath.Dir(in), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in, []byte("fake-input"), 0o600); err != nil {
		t.Fatal(err)
	}
	b2, err := New(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := b2.Serve(context.Background()); err == nil || !strings.Contains(err.Error(), "broker đã chạy") {
		t.Fatalf("second Serve = %v, want broker already running", err)
	}
	if got, err := os.ReadFile(in); err != nil || string(got) != "fake-input" {
		t.Fatalf("running broker's run file after second Serve = %q, %v; want it untouched", got, err)
	}
}
