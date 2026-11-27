package dir

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keygate/internal/transport"
)

func TestRoundTrip(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	a, _ := New(root, "dev_a")
	b, _ := New(root, "dev_b")

	if err := a.PushMember(ctx, 0, []byte(`{"n":0}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.PushMember(ctx, 1, []byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.PushMember(ctx, 1, []byte(`{"n":1}`)); !errors.Is(err, transport.ErrExists) {
		t.Fatalf("dup member: %v", err)
	}
	if err := a.PushMember(ctx, 5, []byte(`x`)); err == nil || errors.Is(err, transport.ErrExists) {
		t.Fatalf("gap member should fail: %v", err)
	}
	for i := uint64(1); i <= 3; i++ {
		if err := a.PushLog(ctx, "dev_a", i, []byte(`{"seq":`+string(rune('0'+i))+`}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.PushLog(ctx, "dev_a", 2, []byte(`{}`)); !errors.Is(err, transport.ErrExists) {
		t.Fatalf("dup log: %v", err)
	}
	if err := a.PushLog(ctx, "dev_b", 1, []byte(`{}`)); err == nil {
		t.Fatal("must refuse foreign log")
	}
	if err := b.PushCheckpoint(ctx, "dev_a", []byte(`{}`)); err == nil {
		t.Fatal("must refuse foreign checkpoint")
	}
	if err := b.PushLog(ctx, "dev_b", 1, []byte(`{"b":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.PushCheckpoint(ctx, "dev_a", []byte(`{"cp":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.PushCheckpoint(ctx, "dev_a", []byte(`{"cp":2}`)); err != nil {
		t.Fatal(err)
	}

	snap, err := b.Pull(ctx, transport.Since{Members: 1, Logs: map[string]uint64{"dev_a": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Members) != 1 || string(snap.Members[0]) != `{"n":1}` {
		t.Fatalf("members: %q", snap.Members)
	}
	if len(snap.Logs["dev_a"]) != 2 || string(snap.Logs["dev_a"][0]) != `{"seq":2}` {
		t.Fatalf("log a: %q", snap.Logs["dev_a"])
	}
	if len(snap.Logs["dev_b"]) != 1 {
		t.Fatalf("log b: %q", snap.Logs["dev_b"])
	}
	if string(snap.Checkpoints["dev_a"]) != `{"cp":2}` {
		t.Fatalf("cp: %q", snap.Checkpoints["dev_a"])
	}
	// Nothing new.
	snap, err = b.Pull(ctx, transport.Since{Members: 2, Logs: map[string]uint64{"dev_a": 3, "dev_b": 1}})
	if err != nil || len(snap.Members) != 0 || len(snap.Logs) != 0 {
		t.Fatalf("expected empty: %v %+v", err, snap)
	}
	// Empty root works.
	e, _ := New(t.TempDir(), "dev_x")
	if _, err := e.Pull(ctx, transport.Since{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "log", "dev_a.kgl")); err != nil {
		t.Fatal(err)
	}
}

func TestTornTailAndSymlink(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	a, _ := New(root, "dev_a")
	if err := a.PushLog(ctx, "dev_a", 1, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "log", "dev_a.kgl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"torn"`) // no trailing newline
	f.Close()
	snap, _ := a.Pull(ctx, transport.Since{})
	if len(snap.Logs["dev_a"]) != 1 || string(snap.Logs["dev_a"][0]) != `{"a":1}` {
		t.Fatalf("torn tail must be absent: %q", snap.Logs["dev_a"])
	}
	if err := a.PushLog(ctx, "dev_a", 1, []byte(`{}`)); !errors.Is(err, transport.ErrExists) {
		t.Fatalf("seq 1 exists: %v", err)
	}
	if err := a.PushLog(ctx, "dev_a", 2, []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if string(data) != "{\"a\":1}\n{\"a\":2}\n" {
		t.Fatalf("file after repair: %q", data)
	}

	// A symlinked log file must not be followed.
	target := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(target, []byte("keep"), 0o600)
	if err := os.Symlink(target, filepath.Join(root, "log", "dev_a2.kgl")); err != nil {
		t.Skip("symlinks unavailable: ", err)
	}
	b, _ := New(root, "dev_a2")
	if err := b.PushLog(ctx, "dev_a2", 1, []byte(`{}`)); err == nil {
		t.Fatal("append through symlink must fail")
	}
	if got, _ := os.ReadFile(target); string(got) != "keep" {
		t.Fatal("symlink target modified")
	}
	if _, err := a.Pull(ctx, transport.Since{}); err != nil {
		t.Fatalf("pull must skip symlinks: %v", err)
	}
}

func TestCheckpointPublicationFailures(t *testing.T) {
	const device = "dev_a"
	const existing = "synthetic existing data"
	body := []byte(`{"checkpoint":1}`)
	ctx := context.Background()
	newChannel := func(t *testing.T) (*Dir, string) {
		t.Helper()
		root := t.TempDir()
		d, err := New(root, device)
		if err != nil {
			t.Fatal(err)
		}
		return d, filepath.Join(root, "checkpoints")
	}
	assertPreserved := func(t *testing.T, path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil || string(data) != existing {
			t.Fatalf("existing data was not preserved: got %q, err=%v", data, err)
		}
	}

	t.Run("checkpoints path is a file", func(t *testing.T) {
		d, path := newChannel(t)
		if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := d.PushCheckpoint(ctx, device, body); err == nil {
			t.Fatal("push reported success when the checkpoints directory is a file")
		}
		if _, err := d.Pull(ctx, transport.Since{}); err == nil {
			t.Fatal("pull treated an invalid checkpoints directory as an empty channel")
		}
		assertPreserved(t, path)
	})

	t.Run("checkpoint path is a directory", func(t *testing.T) {
		d, parent := newChannel(t)
		const checkpoint = device + ".json"
		path := filepath.Join(parent, checkpoint)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(path, "keep")
		if err := os.WriteFile(sentinel, []byte(existing), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := d.PushCheckpoint(ctx, device, body); err == nil {
			t.Fatal("push reported success after checkpoint replacement failed")
		}
		assertPreserved(t, sentinel)
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != checkpoint {
			t.Fatalf("failed push left extra entries in the checkpoints directory: %v", entries)
		}
	})
}

func TestOversizedChannelFiles(t *testing.T) {
	const limit = 64 << 20
	const prefix = "{\"fake\":1}\n"
	wantErr := fmt.Sprintf("file exceeds %d bytes", limit)
	checkLimit := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("error = %v, want %q", err, wantErr)
		}
	}
	for _, tc := range []struct {
		name string
		path string
		push func(context.Context, *Dir) error
	}{
		{name: "members", path: "members.kgl", push: func(ctx context.Context, d *Dir) error {
			return d.PushMember(ctx, 1, []byte(`{"fake":2}`))
		}},
		{name: "log", path: "log/dev_a.kgl", push: func(ctx context.Context, d *Dir) error {
			return d.PushLog(ctx, "dev_a", 2, []byte(`{"fake":2}`))
		}},
		{name: "checkpoint", path: "checkpoints/dev_a.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			d, err := New(root, "dev_a")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, filepath.FromSlash(tc.path))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(prefix), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, limit+1); err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			snap, err := d.Pull(ctx, transport.Since{})
			checkLimit(t, err)
			if len(snap.Members) != 0 || len(snap.Logs) != 0 || len(snap.Checkpoints) != 0 {
				t.Fatal("pull returned data from an oversized file")
			}
			if tc.push != nil {
				checkLimit(t, tc.push(ctx, d))
			}

			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			st, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if st.Size() != limit+1 {
				t.Fatalf("rejected file was resized to %d bytes", st.Size())
			}
			var got [len(prefix)]byte
			if _, err := f.ReadAt(got[:], 0); err != nil {
				t.Fatal(err)
			}
			if string(got[:]) != prefix {
				t.Fatal("rejected file's first record was overwritten")
			}
		})
	}
}
