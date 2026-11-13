package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keygate/internal/devkey"
	"keygate/internal/kcrypto"
	"keygate/internal/members"
	"keygate/internal/record"
	"keygate/internal/recovery"
	"keygate/internal/transport"
)

func newApproverFixture(t *testing.T) (*Store, *recovery.Keys, *Identity) {
	t.Helper()
	if !devkey.PlainAllowed {
		t.Skip("needs -tags kgtest (plain device key backend)")
	}
	t.Setenv(devkey.EnvBackend, "plain")
	home := filepath.Join(t.TempDir(), "kg")
	vault := kcrypto.NewVaultID()
	setup, err := recovery.NewSetup(vault, "a long master password", low)
	if err != nil {
		t.Fatal(err)
	}
	id := NewIdentity("laptop")
	ks, _ := devkey.Open(home, devkey.Options{})
	if err := SaveIdentity(home, id, ks); err != nil {
		t.Fatal(err)
	}
	st, err := Init(home, vault, id, setup.Keys, setup.Salt, setup.Params, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	phone := NewIdentity("iphone")
	b := phone.Public()
	b.Role = members.RoleApprover
	if err := st.AddDevice(setup.Keys.OwnerPriv, b); err != nil {
		t.Fatal(err)
	}
	return st, setup.Keys, phone
}

func TestAddApproverNoWrapNoEpoch(t *testing.T) {
	st, _, phone := newApproverFixture(t)
	ms := st.Members()
	if ms.Count != 4 || ms.Epoch != 1 {
		t.Fatalf("count=%d epoch=%d (approver add must be one event, same epoch)", ms.Count, ms.Epoch)
	}
	if _, ok := ms.Wraps[1][phone.Dev]; ok {
		t.Fatal("approver received a vault-key wrap")
	}
	if len(ms.Approvers()) != 1 || ms.Approvers()[0].ID != phone.Dev || len(ms.KeyHolders()) != 1 {
		t.Fatalf("approvers=%d keyholders=%d", len(ms.Approvers()), len(ms.KeyHolders()))
	}
}

func TestApproverRecordRejected(t *testing.T) {
	st, _, phone := newApproverFixture(t)
	vk, err := st.vaultKey(1)
	if err != nil {
		t.Fatal(err)
	}
	r := &record.Record{V: 1, Vault: st.Vault(), Item: kcrypto.NewItemID(), Dev: phone.Dev, Seq: 1, Epoch: 1, Op: record.OpPut}
	var n [24]byte
	if err := r.EncryptWithNonce(vk, n, record.Plain{Name: "x", Value: "v"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Sign(phone.EdPriv); err != nil {
		t.Fatal(err)
	}
	line, _ := r.Marshal()
	_, err = st.IngestFrom("", transport.Snapshot{Logs: map[string][][]byte{phone.Dev: {line}}})
	if !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("want ErrUnknownDevice, got %v", err)
	}
}

func TestRevokeApprover(t *testing.T) {
	st, keys, phone := newApproverFixture(t)
	if _, err := st.RevokeDevice(keys.OwnerPriv, phone.Dev, "lost"); err != nil {
		t.Fatal(err)
	}
	ms := st.Members()
	if ms.Epoch != 2 || len(ms.Approvers()) != 0 || !ms.Devices[phone.Dev].Revoked {
		t.Fatalf("epoch=%d approvers=%d", ms.Epoch, len(ms.Approvers()))
	}
	if _, ok := ms.Wraps[2][phone.Dev]; ok {
		t.Fatal("wrap for revoked approver")
	}
	if len(ms.Wraps[2]) != 2 { // laptop + recovery
		t.Fatalf("wraps in epoch 2: %d", len(ms.Wraps[2]))
	}
}

func TestPairWords(t *testing.T) {
	const code, nonce = "PMRGIZLWEI5CEZDF", "AAECAwQFBgcICQoLDA0ODw"
	w := PairWords(code, nonce)
	if len(strings.Fields(w)) != 6 {
		t.Fatalf("want 6 words, got %q", w)
	}
	if w != PairWords(" "+strings.ToLower(code[:4])+" "+code[4:], nonce) {
		t.Fatal("code is normalised (case, spaces)")
	}
	if w == PairWords(code, "AAECAwQFBgcICQoLDA0ODx") || w == RequestWords(code) {
		t.Fatal("words must depend on the nonce")
	}
}
