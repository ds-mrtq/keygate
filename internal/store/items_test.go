package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keygate/internal/kcrypto"
	"keygate/internal/members"
	"keygate/internal/record"
	"keygate/internal/transport"
)

// addKeyHolder adds a full (vault-key holding) device and returns its identity.
func addKeyHolder(t *testing.T, st *Store, owner ed25519.PrivateKey, label string) *Identity {
	t.Helper()
	id := NewIdentity(label)
	if err := st.AddDevice(owner, id.Public()); err != nil {
		t.Fatal(err)
	}
	return id
}

// ingestPut makes dev write a put for item on top of parent, as if it arrived through sync.
func ingestPut(t *testing.T, st *Store, dev *Identity, item string, parent *string, p record.Plain) {
	t.Helper()
	st.mu.Lock()
	vk, err := st.vaultKey(st.v.ms.Epoch)
	epoch := st.v.ms.Epoch
	st.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r := &record.Record{V: record.CurrentVer, Vault: st.Vault(), Item: item, Parent: parent, Dev: dev.Dev, Seq: 1, Epoch: epoch, Op: record.OpPut}
	if err := r.Encrypt(vk, p); err != nil {
		t.Fatal(err)
	}
	if err := r.Sign(dev.EdPriv); err != nil {
		t.Fatal(err)
	}
	line, _ := r.Marshal()
	if _, err := st.IngestFrom("", transport.Snapshot{Logs: map[string][][]byte{dev.Dev: {line}}}); err != nil {
		t.Fatal(err)
	}
}

func TestItemLifecycle(t *testing.T) {
	st, _, _ := newApproverFixture(t)
	b, _ := st.Put("", record.Plain{Name: "b/x", Value: "fake-b"})
	a, _ := st.Put("", record.Plain{Name: "a/x", Value: "fake-a"})
	if l := st.List(); len(l) != 2 || l[0].Item != a.Item || l[1].Item != b.Item {
		t.Fatalf("list not sorted by name: %+v", l)
	}
	if it, err := st.FindByName("a/x"); err != nil || it.Item != a.Item {
		t.Fatalf("find: %+v %v", it, err)
	}
	if _, err := st.Delete(kcrypto.NewItemID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete unknown: %v", err)
	}
	if _, err := st.Delete(a.Item); err != nil {
		t.Fatal(err)
	}
	p, _, err := st.Get(a.Item)
	if !errors.Is(err, ErrDeleted) || p.Name != "a/x" || p.Value != "" {
		t.Fatalf("tombstone must keep only the name: %+v %v", p, err)
	}
	if _, err := st.FindByName("a/x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted item still found: %v", err)
	}
	if l := st.List(); !l[0].Deleted || l[1].Deleted {
		t.Fatalf("deleted flags: %+v", l)
	}
	if _, err := st.Put("", record.Plain{Name: "b/x", Value: "fake-b2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.FindByName("b/x"); err == nil || !strings.Contains(err.Error(), "2 items") {
		t.Fatalf("duplicate names must not pick one: %v", err)
	}
}

func TestConflictAndResolve(t *testing.T) {
	st, keys, _ := newApproverFixture(t)
	desk := addKeyHolder(t, st, keys.OwnerPriv, "desktop")
	r, _ := st.Put("", record.Plain{Name: "db/x", Value: "v1"})
	h, _ := r.Hash()
	if _, err := st.Put(r.Item, record.Plain{Name: "db/x", Value: "laptop"}); err != nil {
		t.Fatal(err)
	}
	ingestPut(t, st, desk, r.Item, record.StrPtr(h), record.Plain{Name: "db/x", Value: "desktop"})

	if _, _, err := st.Get(r.Item); !errors.Is(err, ErrConflict) {
		t.Fatalf("get: %v", err)
	}
	if _, err := st.Put(r.Item, record.Plain{Name: "db/x", Value: "v3"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("put over a conflict: %v", err)
	}
	if _, err := st.Delete(r.Item); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete over a conflict: %v", err)
	}
	if c := st.Conflicts(); len(c) != 1 || len(c[0].Heads) != 2 {
		t.Fatalf("conflicts: %+v", c)
	}
	if _, err := st.ResolveConflict(r.Item, "nobody"); err == nil {
		t.Fatal("keep that matches no head accepted")
	}
	if _, err := st.ResolveConflict(r.Item, desk.Dev); err != nil {
		t.Fatal(err)
	}
	p, _, err := st.Get(r.Item)
	if err != nil || p.Value != "desktop" {
		t.Fatalf("resolved: %+v %v", p, err)
	}
	if len(st.Conflicts()) != 0 {
		t.Fatal("conflict still listed")
	}
	if _, err := st.ResolveConflict(r.Item, desk.Dev); err == nil {
		t.Fatal("resolve without a conflict accepted")
	}
}

func TestRevokeKeyHolderReencrypts(t *testing.T) {
	st, keys, _ := newApproverFixture(t)
	desk := addKeyHolder(t, st, keys.OwnerPriv, "desktop")
	live, _ := st.Put("", record.Plain{Name: "live", Value: "fake-live"})
	gone, _ := st.Put("", record.Plain{Name: "gone", Value: "fake-gone"})
	if _, err := st.Delete(gone.Item); err != nil {
		t.Fatal(err)
	}

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := st.RevokeDevice(other, desk.Dev, "lost"); err == nil {
		t.Fatal("revoke signed by a non-owner key accepted")
	}
	if _, err := st.RevokeDevice(keys.OwnerPriv, st.ID.Dev, "self"); err == nil {
		t.Fatal("self revoke accepted")
	}
	n, err := st.RevokeDevice(keys.OwnerPriv, desk.Dev, "lost")
	if err != nil || n != 1 {
		t.Fatalf("revoke: n=%d err=%v (only the live item is re-encrypted)", n, err)
	}
	ms := st.Members()
	if _, err := ms.UnwrapKey(ms.Epoch, desk.Dev, desk.XPriv); err == nil {
		t.Fatal("revoked device can unwrap the new vault key")
	}
	p, rec, err := st.Get(live.Item)
	if err != nil || p.Value != "fake-live" || rec.Epoch != ms.Epoch {
		t.Fatalf("live item after revoke: epoch=%d %v", rec.Epoch, err)
	}
	if n, err := st.ReencryptLive(); err != nil || n != 0 {
		t.Fatalf("second re-encrypt: n=%d err=%v", n, err)
	}
	if _, err := st.RevokeDevice(keys.OwnerPriv, desk.Dev, "again"); err == nil {
		t.Fatal("revoking a revoked device accepted")
	}
}

func TestRevokeApproverByKeyHolder(t *testing.T) {
	st, _, phone := newApproverFixture(t)
	if err := st.RevokeApprover(st.ID.Dev, "x"); err == nil {
		t.Fatal("revoke-approver accepted for a key holder")
	}
	epoch := st.Members().Epoch
	if err := st.RevokeApprover(phone.Dev, "lost"); err != nil {
		t.Fatal(err)
	}
	ms := st.Members()
	if ms.Epoch != epoch || len(ms.Approvers()) != 0 || !ms.Devices[phone.Dev].Revoked {
		t.Fatalf("epoch=%d approvers=%d", ms.Epoch, len(ms.Approvers()))
	}
	if err := st.RevokeApprover(phone.Dev, "again"); err == nil {
		t.Fatal("revoking a revoked approver accepted")
	}
}

func TestDecodeRequest(t *testing.T) {
	phone := NewIdentity("iphone")
	b := phone.Public()
	b.Role = members.RoleApprover
	code := RequestCode(b)
	got, err := DecodeRequest(" " + strings.ToLower(code[:8]) + " " + code[8:] + "\n")
	if err != nil || got.Dev != phone.Dev || got.Role != members.RoleApprover || got.XPub != b.XPub {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	bad := func(mod func(*members.AddBody)) string {
		x := phone.Public()
		mod(&x)
		return RequestCode(x)
	}
	for name, c := range map[string]string{
		"not base32":  "!!!!",
		"not json":    requestEnc.EncodeToString([]byte("nope")),
		"role":        bad(func(x *members.AddBody) { x.Role = "owner" }),
		"empty label": bad(func(x *members.AddBody) { x.Label = "" }),
		"long label":  bad(func(x *members.AddBody) { x.Label = strings.Repeat("a", members.MaxLabel+1) }),
		"device id":   bad(func(x *members.AddBody) { x.Dev = "../../x" }),
	} {
		if _, err := DecodeRequest(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGenesisPin(t *testing.T) {
	st, _, _ := newApproverFixture(t)
	pin := st.GenesisPin()
	ms := st.Members()
	if !pinMatches(pin, ms) || !pinMatches(strings.ToLower(strings.ReplaceAll(pin, "-", " ")), ms) {
		t.Fatalf("pin %q does not match its own vault", pin)
	}
	if pinMatches(GenesisPinOf(kcrypto.NewVaultID(), ms.GenesisHash), ms) {
		t.Fatal("pin of another vault id matches")
	}
	if pinMatches("", ms) {
		t.Fatal("empty pin matches")
	}
}

func TestDeleteLeavesNoPlaintextOnDisk(t *testing.T) {
	st, _, _ := newApproverFixture(t)
	const v1, v2 = "fake-secret-v1-7f3a9c", "fake-secret-v2-c9a3f7"
	r, _ := st.Put("", record.Plain{Name: "db/pass", Value: v1})
	if _, err := st.Put(r.Item, record.Plain{Name: "db/pass", Value: v2}); err != nil {
		t.Fatal(err)
	}
	tomb, err := st.Delete(r.Item)
	if err != nil {
		t.Fatal(err)
	}
	vk, _ := st.vaultKey(tomb.Epoch)
	if p, err := tomb.Decrypt(vk); err != nil || p.Value != "" || p.Name != "db/pass" {
		t.Fatalf("tombstone must carry only the name: %+v %v", p, err)
	}
	err = filepath.WalkDir(st.Home, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(v1)) || bytes.Contains(b, []byte(v2)) {
			t.Errorf("plaintext secret on disk in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRevokedApproverHasNoKeyAfterReopen(t *testing.T) {
	st, keys, phone := newApproverFixture(t)
	if _, err := st.Put("", record.Plain{Name: "a", Value: "fake"}); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeApprover(phone.Dev, "lost"); err != nil {
		t.Fatal(err)
	}
	// a later epoch bump must not wrap the new key for the revoked approver either
	desk := addKeyHolder(t, st, keys.OwnerPriv, "desktop")
	if _, err := st.RevokeDevice(keys.OwnerPriv, desk.Dev, "lost"); err != nil {
		t.Fatal(err)
	}
	home, id := st.Home, st.ID
	st.Close()
	st2, err := Open(home, id)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	ms := st2.Members()
	if d := ms.Devices[phone.Dev]; d == nil || !d.Revoked || len(ms.Approvers()) != 0 {
		t.Fatalf("approver not revoked after reopen: %+v", d)
	}
	for e := uint64(1); e <= ms.Epoch; e++ {
		if _, err := ms.UnwrapKey(e, phone.Dev, phone.XPriv); err == nil {
			t.Fatalf("revoked approver can unwrap the vault key of epoch %d", e)
		}
	}
}

func TestReencryptInterruptedLeavesVaultReadable(t *testing.T) {
	st, keys, _ := newApproverFixture(t)
	desk := addKeyHolder(t, st, keys.OwnerPriv, "desktop")
	want := map[string]string{}
	for _, name := range []string{"a", "b", "c"} {
		r, err := st.Put("", record.Plain{Name: name, Value: "fake-" + name})
		if err != nil {
			t.Fatal(err)
		}
		want[r.Item] = "fake-" + name
	}
	// The epoch is committed to members.kgl, then re-encryption fails on the first write.
	log := logPath(st.Home, st.ID.Dev)
	if err := os.Chmod(log, 0o400); err != nil {
		t.Fatal(err)
	}
	if n, err := st.RevokeDevice(keys.OwnerPriv, desk.Dev, "lost"); err == nil || n != 0 {
		t.Fatalf("revoke with an unwritable log: n=%d err=%v", n, err)
	}
	if err := os.Chmod(log, 0o600); err != nil {
		t.Fatal(err)
	}
	// One item made it to the new epoch before the "crash".
	var first string
	for item := range want {
		if first == "" || item < first {
			first = item
		}
	}
	if _, err := st.Put(first, record.Plain{Name: "a", Value: want[first]}); err != nil {
		t.Fatal(err)
	}
	home, id := st.Home, st.ID
	st.Close()

	st2, err := Open(home, id)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	epoch := st2.Members().Epoch
	if epoch != 2 {
		t.Fatalf("epoch %d", epoch)
	}
	stale := 0
	for item, v := range want {
		p, rec, err := st2.Get(item)
		if err != nil || p.Value != v {
			t.Fatalf("item unreadable after interrupted re-encrypt: %v", err)
		}
		if rec.Epoch < epoch {
			stale++
		}
	}
	if stale != 2 {
		t.Fatalf("stale items %d, want 2", stale)
	}
	if n, err := st2.ReencryptLive(); err != nil || n != 2 {
		t.Fatalf("resume: n=%d err=%v", n, err)
	}
	for item, v := range want {
		if p, rec, err := st2.Get(item); err != nil || p.Value != v || rec.Epoch != epoch {
			t.Fatalf("after resume: epoch=%d err=%v", rec.Epoch, err)
		}
	}
}
