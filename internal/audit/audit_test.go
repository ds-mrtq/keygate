package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit", "ledger.jsonl")
	key := []byte("k-k-k-k-k-k-k-k-k-k-k-k-k-k-k-k")
	anc := filepath.Join(filepath.Dir(p), "..", "state", "audit.head")
	l := Open(p, anc, key)
	zero := 0
	for _, e := range []Entry{
		{Event: EvSet, Secret: "a"},
		{Event: EvGrant, Secret: "a", Approval: "user-presence", Agent: "omp"},
		{Event: EvRun, Secret: "a", Argv: []string{"sql", "/@x"}, Exit: &zero},
	} {
		if err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	n, err := l.Verify()
	if err != nil || n != 3 {
		t.Fatalf("verify: %d %v", n, err)
	}
	es, _ := l.Show(time.Time{})
	if len(es) != 3 || es[2].Argv[0] != "sql" || es[0].Prev != nil || es[1].Prev == nil {
		t.Fatalf("show: %+v", es)
	}
	// since filter
	l.now = func() time.Time { return time.Now().Add(-10 * 24 * time.Hour) }
	l.Append(Entry{Event: EvDeny, Secret: "old"})
	l.now = time.Now
	since, _ := ParseSince("7d", time.Now())
	es, _ = l.Show(since)
	if len(es) != 3 {
		t.Fatalf("since: %d", len(es))
	}

	// wrong key
	if _, err := Open(p, anc, []byte("another-key-another-key-another-")).Verify(); err == nil {
		t.Fatal("wrong key must fail")
	}
	// tamper content
	orig, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(orig), `"secret":"a"`, `"secret":"b"`, 1)), 0o600)
	if _, err := l.Verify(); err == nil {
		t.Fatal("tamper must fail")
	}
	// delete a middle line
	lines := strings.Split(strings.TrimSpace(string(orig)), "\n")
	os.WriteFile(p, []byte(lines[0]+"\n"+lines[2]+"\n"+lines[3]+"\n"), 0o600)
	if _, err := l.Verify(); err == nil {
		t.Fatal("deleted line must fail")
	}
	// restore ok
	os.WriteFile(p, orig, 0o600)
	if _, err := l.Verify(); err != nil {
		t.Fatal(err)
	}
	// truncating the tail (a valid prefix) is caught by the anchor
	os.WriteFile(p, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600)
	if _, err := l.Verify(); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncation: %v", err)
	}
	if err := l.Append(Entry{Event: EvRun}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("append after truncation must refuse: %v", err)
	}
	// deleting the whole ledger is caught too
	os.Remove(p)
	if _, err := l.Verify(); !errors.Is(err, ErrTruncated) {
		t.Fatalf("deleted ledger: %v", err)
	}
	if _, err := l.ShowVerified(time.Time{}); err == nil {
		t.Fatal("show must verify first")
	}
	// anchor tamper
	os.WriteFile(p, orig, 0o600)
	os.WriteFile(anc, []byte(`{"count":1,"head":"x","mac":"y"}`), 0o600)
	if _, err := l.Verify(); err == nil {
		t.Fatal("anchor tamper must fail")
	}
}

func TestEmptyVerify(t *testing.T) {
	d := t.TempDir()
	l := Open(filepath.Join(d, "x.jsonl"), filepath.Join(d, "a.head"), []byte("k"))
	if n, err := l.Verify(); n != 0 || err != nil {
		t.Fatal(n, err)
	}
}

func TestAnchorAfterInterruptedAppend(t *testing.T) {
	for _, tc := range []struct {
		name     string
		anchored int
		wantErr  error
	}{
		{"one entry ahead", 2, nil},
		{"two entries ahead", 1, ErrTruncated},
		{"missing anchor", 0, ErrTruncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path, head := filepath.Join(dir, "ledger.jsonl"), filepath.Join(dir, "audit.head")
			l := Open(path, head, []byte("synthetic audit MAC key"))
			events := []string{EvGrant, EvRun, EvDeny}
			var savedHead []byte
			for i, event := range events {
				if err := l.Append(Entry{Event: event}); err != nil {
					t.Fatal(err)
				}
				if i+1 == tc.anchored {
					var err error
					savedHead, err = os.ReadFile(head)
					if err != nil {
						t.Fatal(err)
					}
				}
			}

			// Leave the fully written ledger with only the older anchor on disk.
			if tc.anchored == 0 {
				if err := os.Remove(head); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(head, savedHead, 0o600); err != nil {
				t.Fatal(err)
			}

			es, err := l.ShowVerified(time.Time{})
			if tc.wantErr == nil {
				if err != nil || len(es) != len(events) || es[len(events)-1].Event != EvDeny {
					t.Fatalf("show with one complete entry ahead: got %v, %v", es, err)
				}
				if err := l.Append(Entry{Event: EvGrantRevoke}); err != nil {
					t.Fatalf("append after interrupted anchor update: %v", err)
				}
				if n, err := l.Verify(); err != nil || n != len(events)+1 {
					t.Fatalf("verify after append: got %d, %v; want %d verified entries", n, err, len(events)+1)
				}
				return
			}

			if len(es) != 0 || !errors.Is(err, tc.wantErr) {
				t.Fatalf("show returned %d entries, %v; want no entries and %v", len(es), err, tc.wantErr)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Append(Entry{Event: EvGrantRevoke}); !errors.Is(err, tc.wantErr) {
				t.Fatalf("append with invalid anchor: got %v, want %v", err, tc.wantErr)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("rejected append modified the ledger")
			}
		})
	}
}
