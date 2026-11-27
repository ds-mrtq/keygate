package git

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"keygate/internal/transport"
)

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func TestRoundTripViaBareRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	bare := t.TempDir()
	gitRun(t, bare, "init", "--bare", "-b", "main")
	w1, w2 := t.TempDir(), t.TempDir()
	for _, w := range []string{w1, w2} {
		gitRun(t, w, "init", "-b", "main")
		gitRun(t, w, "remote", "add", "origin", bare)
	}
	a, err := New(w1, "dev_a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(w2, "dev_b")
	if err != nil {
		t.Fatal(err)
	}

	if err := a.PushMember(ctx, 0, []byte(`{"n":0}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.PushLog(ctx, "dev_a", 1, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.PushCheckpoint(ctx, "dev_a", []byte(`{"cp":"a"}`)); err != nil {
		t.Fatal(err)
	}

	snap, err := b.Pull(ctx, transport.Since{})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Members) != 1 || len(snap.Logs["dev_a"]) != 1 || string(snap.Checkpoints["dev_a"]) != `{"cp":"a"}` {
		t.Fatalf("b pull: %+v", snap)
	}
	if err := b.PushMember(ctx, 0, []byte(`{"n":0}`)); !errors.Is(err, transport.ErrExists) {
		t.Fatalf("dup member: %v", err)
	}
	// Concurrent divergent pushes: b writes its log, then a writes more and pulls b's.
	if err := b.PushLog(ctx, "dev_b", 1, []byte(`{"b":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.PushLog(ctx, "dev_a", 2, []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	snap, err = a.Pull(ctx, transport.Since{Members: 1, Logs: map[string]uint64{"dev_a": 2}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Logs["dev_b"]) != 1 || len(snap.Logs["dev_a"]) != 0 {
		t.Fatalf("a pull: %+v", snap)
	}
}

func TestBatchFlushAcrossDivergentLogs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	for _, tc := range []struct {
		name    string
		badPush bool
	}{
		{name: "rebase and retry"},
		{name: "push destination unavailable", badPush: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			bare := t.TempDir()
			gitRun(t, bare, "init", "--bare", "-b", "main")
			open := func(dev string) (*Git, string) {
				t.Helper()
				w := t.TempDir()
				gitRun(t, w, "init", "-b", "main")
				gitRun(t, w, "remote", "add", "origin", bare)
				g, err := New(w, dev)
				if err != nil {
					t.Fatal(err)
				}
				return g, w
			}
			const devA, devB = "dev_a", "dev_b"
			const logA, logB = `{"a":1}`, `{"b":1}`
			a, aDir := open(devA)
			b, _ := open(devB)
			if err := a.PushMember(ctx, 0, []byte(`{"n":0}`)); err != nil {
				t.Fatal(err)
			}
			a.SetBatch(true)
			if err := a.PushLog(ctx, devA, 1, []byte(logA)); err != nil {
				t.Fatal(err)
			}
			if err := b.PushLog(ctx, devB, 1, []byte(logB)); err != nil {
				t.Fatal(err)
			}
			assertRemote := func(published bool) {
				t.Helper()
				reader, _ := open("dev_reader")
				snap, err := reader.Pull(ctx, transport.Since{})
				if err != nil {
					t.Fatal(err)
				}
				if got := snap.Logs[devB]; len(got) != 1 || string(got[0]) != logB {
					t.Fatalf("expected the peer's record to be preserved, got %q", got)
				}
				got := snap.Logs[devA]
				if !published && len(got) != 0 {
					t.Fatalf("batch was published before a successful flush: %q", got)
				}
				if published && (len(got) != 1 || string(got[0]) != logA) {
					t.Fatalf("expected the batched record to be published once, got %q", got)
				}
			}
			assertRemote(false)
			if tc.badPush {
				gitRun(t, aDir, "config", "remote.origin.pushurl", filepath.Join(t.TempDir(), "missing"))
				if err := a.Flush(ctx); err == nil || !strings.Contains(err.Error(), "git push") {
					t.Fatalf("flush did not report the failed push: %v", err)
				}
				assertRemote(false)
				gitRun(t, aDir, "config", "--unset", "remote.origin.pushurl")
			}
			if err := a.Flush(ctx); err != nil {
				t.Fatalf("flush failed: %v", err)
			}
			assertRemote(true)
		})
	}
}

func TestNoRemoteAndBatch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	w := t.TempDir()
	gitRun(t, w, "init", "-b", "main")
	g, err := New(w, "dev_a")
	if err != nil {
		t.Fatal(err)
	}
	g.SetBatch(true)
	for i := uint64(1); i <= 3; i++ {
		if err := g.PushLog(ctx, "dev_a", i, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := g.Pull(ctx, transport.Since{})
	if err != nil || len(snap.Logs["dev_a"]) != 3 {
		t.Fatalf("%v %+v", err, snap)
	}
	if _, err := New(t.TempDir(), "dev_a"); err == nil {
		t.Fatal("non-repo must fail")
	}
}
