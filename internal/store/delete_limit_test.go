package store

import (
	"testing"

	"keygate/internal/fsx"
	"keygate/internal/record"
)

// Known limitation, documented on `kg delete` (docs/CLI.md) and in its approval prompt: device logs
// are append-only, so after Delete the earlier put record still decrypts for any holder of that
// epoch's vault key. If history erasure is ever added, update the warning and docs with this test.
func TestKnownLimitDeleteKeepsHistoryForKeyHolders(t *testing.T) {
	st, _, _ := newApproverFixture(t)
	const v = "fake-secret-7f3a9c"
	r, _ := st.Put("", record.Plain{Name: "db/pass", Value: v})
	if _, err := st.Delete(r.Item); err != nil {
		t.Fatal(err)
	}
	lines, err := fsx.ReadLines(logPath(st.Home, st.ID.Dev))
	if err != nil {
		t.Fatal(err)
	}
	readable := false
	for _, l := range lines {
		rec, err := record.Parse(l)
		if err != nil {
			t.Fatal(err)
		}
		vk, err := st.vaultKey(rec.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if p, err := rec.Decrypt(vk); err == nil && p.Value == v {
			readable = true
		}
	}
	if !readable {
		t.Fatal("deleted value no longer decrypts: delete semantics changed, update the warning in deleteSecrets and docs/CLI.md")
	}
}
