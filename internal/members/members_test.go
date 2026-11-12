package members

import (
	"errors"
	"testing"

	"keygate/internal/kcrypto"
)

func build(t *testing.T) (events []*Event, ownerPriv []byte, devX [32]byte, recX [32]byte, vk []byte) {
	t.Helper()
	vault := kcrypto.NewVaultID()
	opub, opriv := kcrypto.GenerateSignKey()
	rp, rpub := kcrypto.GenerateX25519()
	dpub, _ := kcrypto.GenerateSignKey()
	dx, dxpub := kcrypto.GenerateX25519()
	dev := kcrypto.NewDeviceID()
	vk = kcrypto.NewVaultKey()
	g, err := New(vault, 0, nil, TypeGenesis, GenesisBody{OwnerPub: kcrypto.B64(opub), RecoveryPub: kcrypto.B64(rpub[:]),
		ArgonSalt: kcrypto.B64(kcrypto.RandBytes(16)), ArgonParams: kcrypto.Argon2Params{T: 1, M: 64, P: 1}, Created: "x"}, opriv)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(vault, 1, g, TypeAdd, AddBody{Dev: dev, Label: "l", EdPub: kcrypto.B64(dpub), XPub: kcrypto.B64(dxpub[:])}, opriv)
	if err != nil {
		t.Fatal(err)
	}
	eb, _ := NewEpochBody(vault, 1, vk, []Recipient{{dev, dxpub}, {RecoveryRcpt, rpub}})
	e, err := New(vault, 2, a, TypeEpoch, eb, opriv)
	if err != nil {
		t.Fatal(err)
	}
	return []*Event{g, a, e}, opriv, dx, rp, vk
}

func lines(evs []*Event) [][]byte {
	var out [][]byte
	for _, e := range evs {
		l, _ := e.Marshal()
		out = append(out, l)
	}
	return out
}

func TestReplayAndUnwrap(t *testing.T) {
	evs, _, dx, rx, vk := build(t)
	st, err := Replay(lines(evs))
	if err != nil {
		t.Fatal(err)
	}
	if st.Epoch != 1 || st.Count != 3 || len(st.Active()) != 1 {
		t.Fatalf("state %+v", st)
	}
	dev := st.Active()[0].ID
	if got, err := st.UnwrapKey(1, dev, dx); err != nil || string(got) != string(vk) {
		t.Fatalf("device unwrap: %v", err)
	}
	if got, err := st.UnwrapKey(1, RecoveryRcpt, rx); err != nil || string(got) != string(vk) {
		t.Fatalf("recovery unwrap: %v", err)
	}
	if _, err := st.UnwrapKey(2, dev, dx); !errors.Is(err, ErrNoWrap) {
		t.Fatalf("want ErrNoWrap, got %v", err)
	}
}

func TestReplayRejects(t *testing.T) {
	evs, _, _, _, _ := build(t)
	// skip an event
	if _, err := Replay(lines([]*Event{evs[0], evs[2]})); !errors.Is(err, ErrChain) {
		t.Fatalf("gap: %v", err)
	}
	// foreign owner signature
	_, evil := kcrypto.GenerateSignKey()
	forged := *evs[1]
	if err := forged.Sign(evil); err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(lines([]*Event{evs[0], &forged})); !errors.Is(err, ErrBadOwnerSig) {
		t.Fatalf("forged: %v", err)
	}
	// modified body keeps old signature
	mod := *evs[1]
	mod.Body = kcrypto.B64([]byte(`{"dev":"dev_aaaaaaaaaa","label":"x","ed_pub":"","x_pub":""}`))
	if _, err := Replay(lines([]*Event{evs[0], &mod})); err == nil {
		t.Fatal("modified body accepted")
	}
}

func TestRevokeNeedsEpoch(t *testing.T) {
	evs, opriv, _, _, _ := build(t)
	st, _ := Replay(lines(evs))
	dev := st.Active()[0].ID
	rev, err := New(st.Vault, 3, evs[2], TypeRevoke, RevokeBody{Dev: dev, Reason: "x", LastSeq: 0}, opriv)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Replay(lines(append(evs, rev)))
	if err != nil || !s2.PendingEpoch || !s2.Devices[dev].Revoked {
		t.Fatalf("revoke: %v", err)
	}
	add, _ := New(st.Vault, 4, rev, TypeAdd, AddBody{Dev: kcrypto.NewDeviceID(), Label: "n", EdPub: kcrypto.B64(kcrypto.RandBytes(32)), XPub: kcrypto.B64(kcrypto.RandBytes(32))}, opriv)
	if _, err := Replay(lines(append(evs, rev, add))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("add after revoke: %v", err)
	}
	// epoch+1 that omits recovery is rejected
	_, xp := kcrypto.GenerateX25519()
	eb, _ := NewEpochBody(st.Vault, 2, kcrypto.NewVaultKey(), []Recipient{{"recovery", xp}})
	ep, _ := New(st.Vault, 4, rev, TypeEpoch, eb, opriv)
	if _, err := Replay(lines(append(evs, rev, ep))); err != nil {
		t.Fatalf("revoked sole device + recovery only epoch should be valid: %v", err)
	}
}

func approverBody() AddBody {
	pub, _ := kcrypto.GenerateSignKey()
	_, xp := kcrypto.GenerateX25519()
	return AddBody{Dev: kcrypto.NewDeviceID(), Label: "iphone", EdPub: kcrypto.B64(pub), XPub: kcrypto.B64(xp[:]), Role: RoleApprover}
}

func TestApproverRole(t *testing.T) {
	evs, opriv, _, _, vk := build(t)
	st, _ := Replay(lines(evs))
	ab := approverBody()
	add, err := New(st.Vault, 3, evs[2], TypeAdd, ab, opriv)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Replay(lines(append(append([]*Event(nil), evs...), add)))
	if err != nil {
		t.Fatalf("add approver: %v", err)
	}
	if len(s2.Active()) != 2 || len(s2.KeyHolders()) != 1 || len(s2.Approvers()) != 1 || s2.Approvers()[0].ID != ab.Dev {
		t.Fatalf("active=%d keyholders=%d approvers=%d", len(s2.Active()), len(s2.KeyHolders()), len(s2.Approvers()))
	}
	// revoke the approver; the new epoch wraps only for the key holder + recovery
	rev, _ := New(st.Vault, 4, add, TypeRevoke, RevokeBody{Dev: ab.Dev, Reason: "x"}, opriv)
	holder := st.Active()[0]
	_, rp := kcrypto.GenerateX25519()
	eb, _ := NewEpochBody(st.Vault, 2, kcrypto.NewVaultKey(), []Recipient{{holder.ID, holder.XPub}, {RecoveryRcpt, rp}})
	ep, _ := New(st.Vault, 5, rev, TypeEpoch, eb, opriv)
	// epoch 2 with approver still active must not need a wrap for it
	s3, err := Replay(lines([]*Event{evs[0], evs[1], evs[2], add, rev, ep}))
	if err != nil || s3.Epoch != 2 || !s3.Devices[ab.Dev].Revoked {
		t.Fatalf("revoke approver: %v", err)
	}
	// holder revoked while the approver stays active: an epoch wrapping only recovery is valid
	revH, _ := New(st.Vault, 4, add, TypeRevoke, RevokeBody{Dev: holder.ID, Reason: "x"}, opriv)
	ebH, _ := NewEpochBody(st.Vault, 2, kcrypto.NewVaultKey(), []Recipient{{RecoveryRcpt, rp}})
	epH, _ := New(st.Vault, 5, revH, TypeEpoch, ebH, opriv)
	if sH, err := Replay(lines([]*Event{evs[0], evs[1], evs[2], add, revH, epH})); err != nil || sH.Epoch != 2 || len(sH.Approvers()) != 1 {
		t.Fatalf("epoch without approver wrap: %v", err)
	}
	// wrap addressed to the approver is rejected (same-epoch add-wrap path)
	var ax [32]byte
	copy(ax[:], mustB64(t, ab.XPub))
	wb, _ := NewEpochBody(st.Vault, 1, vk, []Recipient{{ab.Dev, ax}})
	bad, _ := New(st.Vault, 4, add, TypeEpoch, wb, opriv)
	if _, err := Replay(lines([]*Event{evs[0], evs[1], evs[2], add, bad})); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrap for approver accepted: %v", err)
	}
	// new epoch that includes a wrap for the approver is rejected too (wrong count / wrap for approver)
	rev2, _ := New(st.Vault, 4, add, TypeRevoke, RevokeBody{Dev: holder.ID, Reason: "x"}, opriv)
	eb3, _ := NewEpochBody(st.Vault, 2, kcrypto.NewVaultKey(), []Recipient{{ab.Dev, ax}, {RecoveryRcpt, rp}})
	ep3, _ := New(st.Vault, 5, rev2, TypeEpoch, eb3, opriv)
	if _, err := Replay(lines([]*Event{evs[0], evs[1], evs[2], add, rev2, ep3})); !errors.Is(err, ErrInvalid) {
		t.Fatalf("epoch wrapping an approver accepted: %v", err)
	}
	// unknown role is rejected
	badRole := approverBody()
	badRole.Role = "admin"
	br, _ := New(st.Vault, 3, evs[2], TypeAdd, badRole, opriv)
	if _, err := Replay(lines(append(append([]*Event(nil), evs...), br))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown role accepted: %v", err)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := kcrypto.UnB64(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// revokeApproverFixture: genesis, add key holder, epoch 1, add approver (n=3). Returns the events,
// the owner key, the holder's signing key and the approver's add body and signing key.
func revokeApproverFixture(t *testing.T) (evs []*Event, opriv, hpriv []byte, holder string, ab AddBody, apriv []byte) {
	t.Helper()
	vault := kcrypto.NewVaultID()
	opub, op := kcrypto.GenerateSignKey()
	_, rpub := kcrypto.GenerateX25519()
	hpub, hp := kcrypto.GenerateSignKey()
	_, hx := kcrypto.GenerateX25519()
	holder = kcrypto.NewDeviceID()
	g, _ := New(vault, 0, nil, TypeGenesis, GenesisBody{OwnerPub: kcrypto.B64(opub), RecoveryPub: kcrypto.B64(rpub[:]),
		ArgonSalt: kcrypto.B64(kcrypto.RandBytes(16)), ArgonParams: kcrypto.Argon2Params{T: 1, M: 64, P: 1}, Created: "x"}, op)
	a, _ := New(vault, 1, g, TypeAdd, AddBody{Dev: holder, Label: "laptop", EdPub: kcrypto.B64(hpub), XPub: kcrypto.B64(hx[:])}, op)
	eb, _ := NewEpochBody(vault, 1, kcrypto.NewVaultKey(), []Recipient{{holder, hx}, {RecoveryRcpt, rpub}})
	e, _ := New(vault, 2, a, TypeEpoch, eb, op)
	apub, ap := kcrypto.GenerateSignKey()
	_, ax := kcrypto.GenerateX25519()
	ab = AddBody{Dev: kcrypto.NewDeviceID(), Label: "iphone", EdPub: kcrypto.B64(apub), XPub: kcrypto.B64(ax[:]), Role: RoleApprover}
	add, err := New(vault, 3, e, TypeAdd, ab, op)
	if err != nil {
		t.Fatal(err)
	}
	return []*Event{g, a, e, add}, op, hp, holder, ab, ap
}

func TestRevokeApproverByKeyHolder(t *testing.T) {
	evs, opriv, hpriv, holder, ab, apriv := revokeApproverFixture(t)
	vault := evs[0].Vault
	with := func(more ...*Event) error {
		_, err := Replay(lines(append(append([]*Event(nil), evs...), more...)))
		return err
	}
	rev, _ := New(vault, 4, evs[3], TypeRevokeApprover, RevokeApproverBody{Dev: ab.Dev, By: holder, Reason: "mất máy"}, hpriv)
	st, err := Replay(lines(append(append([]*Event(nil), evs...), rev)))
	if err != nil {
		t.Fatalf("revoke-approver by key holder: %v", err)
	}
	if !st.Devices[ab.Dev].Revoked || len(st.Approvers()) != 0 || st.Epoch != 1 || st.PendingEpoch {
		t.Fatalf("revoked=%v approvers=%d epoch=%d pending=%v", st.Devices[ab.Dev].Revoked, len(st.Approvers()), st.Epoch, st.PendingEpoch)
	}
	// no epoch is pending: the next owner event applies directly
	nextAdd, _ := New(vault, 5, rev, TypeAdd, approverBody(), opriv)
	if err := with(rev, nextAdd); err != nil {
		t.Fatalf("owner event after revoke-approver: %v", err)
	}
	// signed by the approver itself, or naming the holder but signed by another key
	selfRev, _ := New(vault, 4, evs[3], TypeRevokeApprover, RevokeApproverBody{Dev: ab.Dev, By: ab.Dev}, apriv)
	if err := with(selfRev); !errors.Is(err, ErrInvalid) {
		t.Fatalf("approver as signer accepted: %v", err)
	}
	forged, _ := New(vault, 4, evs[3], TypeRevokeApprover, RevokeApproverBody{Dev: ab.Dev, By: holder}, opriv)
	if err := with(forged); !errors.Is(err, ErrBadOwnerSig) {
		t.Fatalf("signature by another key accepted: %v", err)
	}
	// a body with an extra case-variant key is not canonical
	nc := &Event{V: 1, Vault: vault, N: 4, Type: TypeRevokeApprover,
		Body: kcrypto.B64([]byte(`{"dev":"` + holder + `","by":"` + holder + `","reason":"","Dev":"` + ab.Dev + `"}`))}
	h3, _ := evs[3].Hash()
	nc.Prev = &h3
	_ = nc.Sign(hpriv)
	if err := with(nc); !errors.Is(err, ErrMalformed) {
		t.Fatalf("non-canonical revoke-approver body accepted: %v", err)
	}
	// a key holder is not a valid target, and an already revoked approver neither
	holderRev, _ := New(vault, 4, evs[3], TypeRevokeApprover, RevokeApproverBody{Dev: holder, By: holder}, hpriv)
	if err := with(holderRev); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoke-approver of a key holder accepted: %v", err)
	}
	again, _ := New(vault, 5, rev, TypeRevokeApprover, RevokeApproverBody{Dev: ab.Dev, By: holder}, hpriv)
	if err := with(rev, again); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second revoke of the same approver accepted: %v", err)
	}
	// a revoked key holder can no longer sign
	revH, _ := New(vault, 4, evs[3], TypeRevoke, RevokeBody{Dev: holder, Reason: "x"}, opriv)
	_, rp := kcrypto.GenerateX25519()
	ebH, _ := NewEpochBody(vault, 2, kcrypto.NewVaultKey(), []Recipient{{RecoveryRcpt, rp}})
	epH, _ := New(vault, 5, revH, TypeEpoch, ebH, opriv)
	late, _ := New(vault, 6, epH, TypeRevokeApprover, RevokeApproverBody{Dev: ab.Dev, By: holder}, hpriv)
	if err := with(revH, epH, late); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoked key holder signed a revoke-approver: %v", err)
	}
}
