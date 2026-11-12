package syncer

import (
	"os"
	"testing"

	"crypto/ed25519"
	"keygate/internal/kcrypto"
	"keygate/internal/members"
	"keygate/internal/record"
	"keygate/internal/store"
)

func osReadDir(d string) ([]os.DirEntry, error) { return os.ReadDir(d) }
func osReadFile(p string) ([]byte, error)       { return os.ReadFile(p) }
func osWriteFile(p string, b []byte) error      { return os.WriteFile(p, b, 0o600) }

// forgeAdd builds an add event for forged that follows the channel's last event but is signed by a non-owner key.
func forgeAdd(w *world, b *device, fakeOwner ed25519.PrivateKey, forged *store.Identity) ([]byte, error) {
	st := b.st.Members()
	var last *members.Event
	for n := range w.ch.Members {
		if uint64(n) == st.Count-1 {
			e, err := members.Parse(w.ch.Members[n])
			if err != nil {
				return nil, err
			}
			last = e
		}
	}
	ev, err := members.New(w.vault, st.Count, last, members.TypeAdd, forged.Public(), fakeOwner)
	if err != nil {
		return nil, err
	}
	return ev.Marshal()
}

// forgeNext returns a validly signed record by d (a revoked device) continuing its channel log, and its seq.
func forgeNext(t *testing.T, w *world, d *device) ([]byte, uint64) {
	t.Helper()
	dev := d.st.ID.Dev
	last := uint64(len(w.ch.Logs[dev]))
	prev, err := record.Parse(w.ch.Logs[dev][last])
	if err != nil {
		t.Fatal(err)
	}
	h, _ := prev.Hash()
	r := &record.Record{V: 1, Vault: w.vault, Item: kcrypto.NewItemID(), Dev: dev, Seq: last + 1, Prev: record.StrPtr(h), Epoch: 1, Op: record.OpPut}
	if err := r.Encrypt(kcrypto.NewVaultKey(), plain("x", "y")); err != nil {
		t.Fatal(err)
	}
	if err := r.Sign(d.st.ID.EdPriv); err != nil {
		t.Fatal(err)
	}
	line, _ := r.Marshal()
	return line, last + 1
}

// forgeAt returns a validly signed record by d at the given seq (different content from any original).
func forgeAt(t *testing.T, w *world, d *device, seq uint64) ([]byte, string) {
	t.Helper()
	r := &record.Record{V: 1, Vault: w.vault, Item: kcrypto.NewItemID(), Dev: d.st.ID.Dev, Seq: seq, Epoch: 1, Op: record.OpPut}
	if seq > 1 {
		t.Fatal("forgeAt supports seq 1 only")
	}
	if err := r.Encrypt(kcrypto.NewVaultKey(), plain("evil", "x")); err != nil {
		t.Fatal(err)
	}
	if err := r.Sign(d.st.ID.EdPriv); err != nil {
		t.Fatal(err)
	}
	line, _ := r.Marshal()
	h, _ := r.Hash()
	return line, h
}
