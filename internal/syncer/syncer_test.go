package syncer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keygate/internal/checkpoint"
	"keygate/internal/kcrypto"
	"keygate/internal/record"
	"keygate/internal/recovery"
	"keygate/internal/store"
	"keygate/internal/transport"
)

func plain(name, value string) record.Plain {
	return record.Plain{Name: name, Value: value, Env: "test", Kind: "env", EnvName: "X"}
}

func TestRoundTrip(t *testing.T) {
	w := newWorld(t)
	b := w.addDevice("laptop-b")
	item := put(t, w.a, "", "db/test/pass", "s3cret-A")
	w.mustSync(w.a)
	w.mustSync(b)
	p, _, err := b.st.Get(item)
	if err != nil || p.Value != "s3cret-A" || p.Name != "db/test/pass" {
		t.Fatalf("b get: %+v %v", p, err)
	}
	if w.a.st.Fingerprint() != b.st.Fingerprint() {
		t.Fatalf("fingerprints differ: %q vs %q", w.a.st.Fingerprint(), b.st.Fingerprint())
	}
	// reopen from disk re-verifies everything
	if _, err := store.Open(b.st.Home, b.st.ID); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// secret never appears in any local file
	checkNoPlaintext(t, b.st.Home, "s3cret-A")
}

func checkNoPlaintext(t *testing.T, home, needle string) {
	t.Helper()
	var walk func(dir string)
	walk = func(dir string) {
		ents, _ := osReadDir(dir)
		for _, e := range ents {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				walk(p)
				continue
			}
			if bts, _ := osReadFile(p); bytes.Contains(bts, []byte(needle)) {
				t.Errorf("plaintext secret found in %s", p)
			}
		}
	}
	walk(home)
}

func TestAttacks(t *testing.T) {
	// base builds: A with 3 records, B joined, everything synced.
	t.Run("modify", func(t *testing.T) {
		w := newWorld(t)
		b := w.addDevice("b")
		for i := 0; i < 3; i++ {
			put(t, w.a, "", "n", "v")
		}
		w.mustSync(w.a)
		dev := w.a.st.ID.Dev
		var r record.Record
		if err := json.Unmarshal(w.ch.Logs[dev][2], &r); err != nil {
			t.Fatal(err)
		}
		ct, _ := kcrypto.UnB64(r.CT)
		ct[0] ^= 0xff
		r.CT = kcrypto.B64(ct)
		w.ch.Logs[dev][2], _ = json.Marshal(&r)
		err := w.sync(b)
		if !errors.Is(err, ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, got %v", err)
		}
		assertNoLog(t, b, dev)
	})
	t.Run("insert-device", func(t *testing.T) {
		w := newWorld(t)
		b := w.addDevice("b")
		put(t, w.a, "", "n", "v")
		w.mustSync(w.a)
		// attacker: unknown device with its own valid keys signs a record
		pub, priv := kcrypto.GenerateSignKey()
		_ = pub
		evil := kcrypto.NewDeviceID()
		r := &record.Record{V: 1, Vault: w.vault, Item: kcrypto.NewItemID(), Dev: evil, Seq: 1, Epoch: 1, Op: record.OpPut}
		if err := r.Encrypt(kcrypto.NewVaultKey(), plain("evil", "x")); err != nil {
			t.Fatal(err)
		}
		if err := r.Sign(priv); err != nil {
			t.Fatal(err)
		}
		line, _ := r.Marshal()
		w.ch.Logs[evil] = map[uint64][]byte{1: line}
		err := w.sync(b)
		if !errors.Is(err, ErrUnknownDevice) {
			t.Fatalf("want ErrUnknownDevice, got %v", err)
		}
		assertNoLog(t, b, evil)
	})
	t.Run("delete-middle", func(t *testing.T) {
		w := newWorld(t)
		b := w.addDevice("b")
		for i := 0; i < 3; i++ {
			put(t, w.a, "", "n", "v")
		}
		w.mustSync(w.a)
		delete(w.ch.Logs[w.a.st.ID.Dev], 2)
		err := w.sync(b)
		if !errors.Is(err, ErrBrokenChain) {
			t.Fatalf("want ErrBrokenChain, got %v", err)
		}
		assertNoLog(t, b, w.a.st.ID.Dev)
	})
	t.Run("rollback", func(t *testing.T) {
		w := newWorld(t)
		b := w.addDevice("b")
		for i := 0; i < 3; i++ {
			put(t, w.a, "", "n", "v")
		}
		w.mustSync(w.a)
		w.mustSync(b)
		delete(w.ch.Logs[w.a.st.ID.Dev], 3)
		err := w.sync(b)
		if !errors.Is(err, ErrRollback) {
			t.Fatalf("want ErrRollback, got %v", err)
		}
	})
	t.Run("hide", func(t *testing.T) {
		w := newWorld(t)
		b := w.addDevice("b")
		c := w.addDevice("c")
		for i := 0; i < 3; i++ {
			put(t, w.a, "", "n", "v")
		}
		w.mustSync(w.a)
		w.mustSync(b) // b's checkpoint now says it saw A up to seq 3
		// channel withholds A's last record from c
		delete(w.ch.Logs[w.a.st.ID.Dev], 3)
		err := w.sync(c)
		if !errors.Is(err, ErrHidden) {
			t.Fatalf("want ErrHidden, got %v", err)
		}
	})
}

func assertNoLog(t *testing.T, d *device, dev string) {
	t.Helper()
	if _, err := osReadFile(filepath.Join(d.st.Home, "log", dev+".kgl")); err == nil {
		// the file may exist only if valid records were appended; a corrupt batch must write nothing
		t.Errorf("log of %s was written despite verification failure", dev)
	}
}

func TestConflictAndResolve(t *testing.T) {
	w := newWorld(t)
	b := w.addDevice("b")
	item := put(t, w.a, "", "db/test/pass", "v0")
	w.mustSync(w.a)
	w.mustSync(b)
	// concurrent edits from the same parent
	put(t, w.a, item, "db/test/pass", "from-a")
	put(t, b, item, "db/test/pass", "from-b")
	w.mustSync(w.a)
	w.mustSync(b)
	w.mustSync(w.a)
	for _, d := range []*device{w.a, b} {
		if _, _, err := d.st.Get(item); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("want ErrConflict, got %v", err)
		}
		if _, err := d.st.Put(item, plain("db/test/pass", "x")); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("put on conflict: %v", err)
		}
		cs := d.st.Conflicts()
		if len(cs) != 1 || len(cs[0].Heads) != 2 || cs[0].Name != "db/test/pass" {
			t.Fatalf("conflicts: %+v", cs)
		}
	}
	if _, err := w.a.st.ResolveConflict(item, b.st.ID.Dev); err != nil {
		t.Fatal(err)
	}
	w.mustSync(w.a)
	w.mustSync(b)
	for _, d := range []*device{w.a, b} {
		p, _, err := d.st.Get(item)
		if err != nil || p.Value != "from-b" {
			t.Fatalf("after resolve: %+v %v", p, err)
		}
		if len(d.st.Conflicts()) != 0 {
			t.Fatal("still in conflict")
		}
	}
}

func TestTombstone(t *testing.T) {
	w := newWorld(t)
	b := w.addDevice("b")
	item := put(t, w.a, "", "tmp/secret", "zzz")
	w.mustSync(w.a)
	w.mustSync(b)
	if _, err := b.st.Delete(item); err != nil {
		t.Fatal(err)
	}
	w.mustSync(b)
	w.mustSync(w.a)
	p, _, err := w.a.st.Get(item)
	if !errors.Is(err, store.ErrDeleted) || p.Name != "tmp/secret" || p.Value != "" {
		t.Fatalf("tombstone: %+v %v", p, err)
	}
	if _, err := w.a.st.FindByName("tmp/secret"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByName deleted: %v", err)
	}
	if li := w.a.st.List(); len(li) != 1 || !li[0].Deleted {
		t.Fatalf("list: %+v", li)
	}
}

func TestRevokeEpochReencrypt(t *testing.T) {
	w := newWorld(t)
	b := w.addDevice("b")
	c := w.addDevice("c")
	item := put(t, w.a, "", "prod/db", "old-secret")
	item2 := put(t, w.a, "", "other", "o2")
	w.mustSync(w.a)
	w.mustSync(b)
	put(t, b, "", "from-b", "bv") // b writes one record before being revoked
	w.mustSync(b)
	w.mustSync(c)
	w.mustSync(w.a) // A sees b's record, so last_seq covers it
	if _, _, err := b.st.Get(item); err != nil {
		t.Fatal(err)
	}
	n, err := w.a.st.RevokeDevice(w.setup.Keys.OwnerPriv, b.st.ID.Dev, "lost laptop")
	if err != nil || n != 3 {
		t.Fatalf("revoke: n=%d err=%v", n, err)
	}
	if w.a.st.Epoch() != 2 {
		t.Fatalf("epoch %d", w.a.st.Epoch())
	}
	w.mustSync(w.a)
	// c (still member) reads new epoch
	w.mustSync(c)
	w.mustSync(c)
	for _, it := range []string{item, item2} {
		p, r, err := c.st.Get(it)
		if err != nil || r.Epoch != 2 || p.Value == "" {
			t.Fatalf("c get: %+v %v", r, err)
		}
	}
	// revoked b: its own state may refuse to sync new events? it syncs (read-only attacker view) but cannot decrypt epoch 2
	_ = w.sync(b)
	if _, _, err := b.st.Get(item); err == nil {
		t.Fatal("revoked device decrypted new-epoch item")
	} else if !errors.Is(err, store.ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v", err)
	}
	// revoked device may not write: its own writes are refused
	if _, err := b.st.Put("", plain("x", "y")); err == nil {
		t.Fatal("revoked device could write")
	}
	// records b forges after revocation are rejected by others
	line, seq := forgeNext(t, w, b)
	w.ch.Logs[b.st.ID.Dev][seq] = line
	if err := w.sync(c); err != nil {
		t.Fatalf("post-revoke record must be dropped, not fatal: %v", err)
	}
	if err := w.sync(w.a); err != nil {
		t.Fatalf("owner sync after forged record: %v", err)
	}
	for _, d := range []*device{c, w.a} {
		if n := len(d.st.Members().Devices); n == 0 {
			t.Fatal("members lost")
		}
		if raw, _ := osReadFile(filepath.Join(d.st.Home, "log", b.st.ID.Dev+".kgl")); bytes.Contains(raw, line) {
			t.Fatal("record above last_seq was stored")
		}
	}
}

func TestRecovery(t *testing.T) {
	w := newWorld(t)
	b := w.addDevice("b")
	item := put(t, w.a, "", "prod/db", "keep-me")
	w.mustSync(w.a)
	_ = b
	// everything on the channel; "laptop lost": recover on a fresh home from pwd + paper key
	st := w.setup
	snap, _ := w.ch.Pull(w.ctx, transport.Since{})
	state := w.a.st.Members()
	paper, err := recovery.ParsePaperKey(st.PaperKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := recovery.Derive(state.Vault, testPwd, state.ArgonSalt, state.ArgonParams, paper)
	if err != nil {
		t.Fatal(err)
	}
	id := store.NewIdentity("replacement")
	home := filepath.Join(t.TempDir(), "fresh")
	r, err := store.Recover(home, id, keys, snap, "")
	if err != nil {
		t.Fatal(err)
	}
	rd := &device{st: r, sy: &Syncer{Store: r, T: w.ch}}
	w.mustSync(rd)
	p, _, err := r.Get(item)
	if err != nil || p.Value != "keep-me" {
		t.Fatalf("recovered get: %+v %v", p, err)
	}
	// the new device is a member, and other devices can see it after sync
	w.mustSync(w.a)
	if d, ok := w.a.st.Members().Devices[id.Dev]; !ok || d.Revoked {
		t.Fatal("recovered device not registered")
	}
	// and it can write
	put(t, rd, item, "prod/db", "rotated")
	w.mustSync(rd)
	w.mustSync(w.a)
	if p, _, err := w.a.st.Get(item); err != nil || p.Value != "rotated" {
		t.Fatalf("a get: %+v %v", p, err)
	}
}

func TestWrongPaperKey(t *testing.T) {
	w := newWorld(t)
	snap, _ := w.ch.Pull(w.ctx, transport.Since{})
	state := w.a.st.Members()
	wrong := recovery.EncodePaperKey(kcrypto.RandBytes(32))
	paper, err := recovery.ParsePaperKey(wrong)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := recovery.Derive(state.Vault, testPwd, state.ArgonSalt, state.ArgonParams, paper)
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(t.TempDir(), "fresh")
	if _, err := store.Recover(home, store.NewIdentity("x"), keys, snap, ""); !errors.Is(err, store.ErrWrongKeys) {
		t.Fatalf("wrong paper key: want ErrWrongKeys, got %v", err)
	}
	// wrong password with the right paper key fails too
	paper2, _ := recovery.ParsePaperKey(w.setup.PaperKey)
	keys2, _ := recovery.Derive(state.Vault, "wrong password!!", state.ArgonSalt, state.ArgonParams, paper2)
	if _, err := store.Recover(home, store.NewIdentity("x"), keys2, snap, ""); !errors.Is(err, store.ErrWrongKeys) {
		t.Fatalf("wrong password: want ErrWrongKeys, got %v", err)
	}
	if _, err := osReadFile(filepath.Join(home, "members.kgl")); err == nil {
		t.Fatal("failed recovery left files behind")
	}
}

func TestVerifyViaFork(t *testing.T) {
	w := newWorld(t)
	b := w.addDevice("b")
	put(t, w.a, "", "n", "v")
	w.mustSync(w.a)
	w.mustSync(b)
	// second channel (e.g. git) is an honest copy
	g := newFake("git")
	snap, err := w.ch.Pull(w.ctx, transport.Since{})
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range snap.Members {
		g.Members[i] = l
	}
	for d, ls := range snap.Logs {
		g.Logs[d] = map[uint64][]byte{}
		for i, l := range ls {
			g.Logs[d][uint64(i+1)] = l
		}
	}
	for d, c := range snap.Checkpoints {
		g.CPs[d] = c
	}
	want := w.a.st.Fingerprint()
	// A local-only record must not affect verification of the two channels.
	put(t, w.a, "", "n2", "v2")
	got, err := VerifyVia(w.ctx, w.a.st, w.ch, g)
	if err != nil {
		t.Fatalf("honest channels: %v", err)
	}
	if got != want {
		t.Fatalf("honest channels: fingerprint = %q, want %q", got, want)
	}
	// Publishing the record to just one channel makes the views diverge.
	w.mustSync(w.a)
	if fp, err := VerifyVia(w.ctx, w.a.st, w.ch, g); fp != "" || !errors.Is(err, ErrFork) {
		t.Fatalf("divergent channels: got (%q, %v), want empty fingerprint and ErrFork", fp, err)
	}
}

type pullErrorChannel struct {
	transport.Transport
	err error
}

func (c pullErrorChannel) Pull(context.Context, transport.Since) (transport.Snapshot, error) {
	return transport.Snapshot{}, c.err
}

func TestVerifyViaChannelErrors(t *testing.T) {
	w := newWorld(t)
	foreign := newWorld(t).ch
	foreign.name = "foreign"
	unavailable := errors.New("test channel unavailable")
	offline := pullErrorChannel{Transport: newFake("offline"), err: unavailable}

	for _, tt := range []struct {
		name               string
		primary, secondary transport.Transport
		failed             transport.Transport
		wantErr            error
	}{
		{"primary pull fails", offline, w.ch, offline, unavailable},
		{"secondary pull fails", w.ch, offline, offline, unavailable},
		{"foreign primary vault", foreign, w.ch, foreign, store.ErrBrokenChain},
		{"foreign secondary vault", w.ch, foreign, foreign, store.ErrBrokenChain},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fp, err := VerifyVia(w.ctx, w.a.st, tt.primary, tt.secondary)
			if fp != "" || !errors.Is(err, tt.wantErr) {
				t.Fatalf("got (%q, %v), want empty fingerprint and %v", fp, err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.failed.Name()+":") {
				t.Fatalf("error %q does not name failing channel %q", err, tt.failed.Name())
			}
		})
	}
}

func TestLocalTamper(t *testing.T) {
	w := newWorld(t)
	put(t, w.a, "", "n", "v")
	w.mustSync(w.a)
	// editing local.json breaks its MAC
	p := filepath.Join(w.a.st.Home, "state", "local.json")
	b, _ := osReadFile(p)
	b = bytes.Replace(b, []byte(`"members_n": 3`), []byte(`"members_n": 1`), 1)
	osWriteFile(p, b)
	if _, err := store.Open(w.a.st.Home, w.a.st.ID); !errors.Is(err, store.ErrLocalState) {
		t.Fatalf("want ErrLocalState, got %v", err)
	}
}

// A member event signed by a non-owner key is rejected as ErrUnknownDevice.
func TestForgedMemberEvent(t *testing.T) {
	// a member event signed by a non-owner key is also ErrUnknownDevice
	w := newWorld(t)
	b := w.addDevice("b")
	_, fakeOwner := kcrypto.GenerateSignKey()
	forged := store.NewIdentity("evil")
	// forge using a second vault state: sign an add with the wrong key
	other, err := forgeAdd(w, b, fakeOwner, forged)
	if err != nil {
		t.Fatal(err)
	}
	w.ch.Members[len(w.ch.Members)] = other
	if err := w.sync(b); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("want ErrUnknownDevice, got %v", err)
	}
}

// M1: the revoked device's record at last_seq must have exactly the hash the owner pinned.
func TestRevokeLastHashPinned(t *testing.T) {
	w := newWorld(t)
	b := w.addDevice("b")
	c := w.addDevice("c")
	put(t, b, "", "from-b", "bv")
	w.mustSync(b)
	w.mustSync(w.a)
	if _, err := w.a.st.RevokeDevice(w.setup.Keys.OwnerPriv, b.st.ID.Dev, "x"); err != nil {
		t.Fatal(err)
	}
	w.mustSync(w.a)
	// the key holder re-signs a different record at seq 1; c never saw the original
	forged, _ := forgeAt(t, w, b, 1)
	w.ch.Logs[b.st.ID.Dev][1] = forged
	if err := w.sync(c); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("want ErrBrokenChain, got %v", err)
	}
}

// M2: a revoked device's checkpoint is ignored.
func TestRevokedCheckpointIgnored(t *testing.T) {
	w := newWorld(t)
	b := w.addDevice("b")
	c := w.addDevice("c")
	put(t, w.a, "", "n", "v")
	w.mustSync(w.a)
	w.mustSync(b)
	w.mustSync(w.a)
	if _, err := w.a.st.RevokeDevice(w.setup.Keys.OwnerPriv, b.st.ID.Dev, "x"); err != nil {
		t.Fatal(err)
	}
	w.mustSync(w.a)
	cp := &checkpoint.Checkpoint{V: 1, Vault: w.vault, Dev: b.st.ID.Dev, Time: "t", MembersN: 999, Seen: map[string]uint64{w.a.st.ID.Dev: 999}}
	cp.Sign(b.st.ID.EdPriv)
	w.ch.CPs[b.st.ID.Dev], _ = cp.Marshal()
	if err := w.sync(c); err != nil {
		t.Fatalf("revoked checkpoint must be ignored: %v", err)
	}
}

// L7: parent/merge may not point into another item.
func TestCrossItemReference(t *testing.T) {
	w := newWorld(t)
	b := w.addDevice("b")
	put(t, w.a, "", "x", "1")
	put(t, w.a, "", "y", "2")
	w.mustSync(w.a)
	dev := w.a.st.ID.Dev
	r1, _ := record.Parse(w.ch.Logs[dev][1])
	r2, _ := record.Parse(w.ch.Logs[dev][2])
	h1, _ := r1.Hash()
	h2, _ := r2.Hash()
	r := &record.Record{V: 1, Vault: w.vault, Item: r2.Item, Parent: record.StrPtr(h1), Dev: dev, Seq: 3, Prev: record.StrPtr(h2), Epoch: 1, Op: record.OpPut}
	if err := r.Encrypt(kcrypto.NewVaultKey(), plain("y", "z")); err != nil {
		t.Fatal(err)
	}
	if err := r.Sign(w.a.st.ID.EdPriv); err != nil {
		t.Fatal(err)
	}
	w.ch.Logs[dev][3], _ = r.Marshal()
	if err := w.sync(b); !errors.Is(err, record.ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

// L8: syncing to a second, empty channel populates it instead of reporting a rollback.
func TestSecondChannelPopulated(t *testing.T) {
	w := newWorld(t)
	put(t, w.a, "", "n", "v")
	w.mustSync(w.a)
	g := newFake("git")
	sy := &Syncer{Store: w.a.st, T: g}
	res, err := sy.Sync(w.ctx)
	if err != nil {
		t.Fatalf("empty second channel: %v", err)
	}
	if res.Pushed.Records != 1 || res.Pushed.Members != 3 || len(g.Logs[w.a.st.ID.Dev]) != 1 {
		t.Fatalf("not populated: %+v", res)
	}
	// but once the channel has been populated, losing lines is a rollback again
	delete(g.Logs[w.a.st.ID.Dev], 1)
	if _, err := sy.Sync(w.ctx); !errors.Is(err, ErrRollback) {
		t.Fatalf("want ErrRollback, got %v", err)
	}
	// both channels still agree
	g2 := newFake("mirror")
	if _, err := (&Syncer{Store: w.a.st, T: g2}).Sync(w.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVia(w.ctx, w.a.st, w.ch, g2); err != nil {
		t.Fatalf("verify-via after populate: %v", err)
	}
}

// ErrExists must be backed by a byte-identical line on the channel.
func TestPushExistsMismatch(t *testing.T) {
	w := newWorld(t)
	put(t, w.a, "", "n", "v")
	dev := w.a.st.ID.Dev
	w.ch.Logs[dev] = map[uint64][]byte{1: []byte(`{"junk":true}`)}
	w.ch.Hide = map[string]map[uint64]bool{dev: {1: true}}
	if err := w.sync(w.a); !errors.Is(err, ErrForkChannel) {
		t.Fatalf("want ErrForkChannel, got %v", err)
	}
}

// C1: Join requires the genesis pin of a trusted device.
func TestJoinPin(t *testing.T) {
	w := newWorld(t)
	id := store.NewIdentity("late")
	if err := w.a.st.AddDevice(w.setup.Keys.OwnerPriv, id.Public()); err != nil {
		t.Fatal(err)
	}
	w.mustSync(w.a)
	snap, _ := w.ch.Pull(w.ctx, transport.Since{})
	for _, pin := range []string{"", "AAAA-BBBB", store.GenesisPinOf(kcrypto.NewVaultID(), w.a.st.Members().GenesisHash)} {
		if _, err := store.Join(filepath.Join(t.TempDir(), "x"), id, snap, pin); !errors.Is(err, store.ErrPin) {
			t.Fatalf("pin %q: want ErrPin, got %v", pin, err)
		}
	}
	pin := w.a.st.GenesisPin()
	if len(pin) != 29 || pin != strings.ToUpper(pin) { // 6 groups of 4 + 5 dashes? 24 chars + 5 dashes
		t.Fatalf("pin format %q", pin)
	}
	st, err := store.Join(filepath.Join(t.TempDir(), "ok"), id, snap, strings.ToLower(pin))
	if err != nil {
		t.Fatalf("join with right pin: %v", err)
	}
	if st.GenesisPin() != pin {
		t.Fatal("pin differs after join")
	}
	// a channel serving a forged vault (own genesis + add for the victim) fails the pin
	evil := newWorld(t)
	if err := evil.a.st.AddDevice(evil.setup.Keys.OwnerPriv, id.Public()); err != nil {
		t.Fatal(err)
	}
	evil.mustSync(evil.a)
	forged, _ := evil.ch.Pull(evil.ctx, transport.Since{})
	if _, err := store.Join(filepath.Join(t.TempDir(), "forged"), id, forged, pin); !errors.Is(err, store.ErrPin) {
		t.Fatalf("forged vault: want ErrPin, got %v", err)
	}
}

// L3: a torn final line in a local log is truncated on Open.
func TestTornLineRepaired(t *testing.T) {
	w := newWorld(t)
	put(t, w.a, "", "n", "v")
	p := filepath.Join(w.a.st.Home, "log", w.a.st.ID.Dev+".kgl")
	before, _ := osReadFile(p)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"v":1,"vault":"vl`)
	f.Close()
	w.a.st.Close()
	st, err := store.Open(w.a.st.Home, w.a.st.ID)
	if err != nil {
		t.Fatalf("open with torn line: %v", err)
	}
	after, _ := osReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("torn tail not truncated")
	}
	_ = st
}

var _ = ed25519.PublicKeySize
