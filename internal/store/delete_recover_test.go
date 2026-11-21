package store

import (
	"testing"

	"keygate/internal/fsx"
	"keygate/internal/record"
)

// Delete must leave no recoverable secret: no line of the on-disk log may decrypt to the old value.
func TestDeleteLeavesNoRecoverableValue(t *testing.T) {
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
			t.Fatalf("deleted value still decrypts from log record seq %d", rec.Seq)
		}
	}
}
