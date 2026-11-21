package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"keygate/internal/checkpoint"
	"keygate/internal/kcrypto"
	"keygate/internal/record"
	"keygate/internal/recovery"
	"keygate/internal/transport"
)

func fullSnapshot(st *Store) transport.Snapshot {
	snap := transport.Snapshot{Members: append([][]byte(nil), st.v.mlines...), Logs: map[string][][]byte{}}
	for d, l := range st.v.logs {
		snap.Logs[d] = append([][]byte(nil), l.lines...)
	}
	return snap
}

func checkpointBytes(t *testing.T, cp *checkpoint.Checkpoint, id *Identity) []byte {
	t.Helper()
	cp.Sign(id.EdPriv)
	b, err := cp.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func requireError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func requireCleanHome(t *testing.T, home string) {
	t.Helper()
	for _, p := range []string{membersPath(home), logDir(home), cpDir(home), filepath.Join(home, "state"), vaultPath(home)} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("not cleaned: %s: %v", p, err)
		}
	}
}

func TestVerifyCheckpoints(t *testing.T) {
	st, keys, phone := newApproverFixture(t)
	desk := addKeyHolder(t, st, keys.OwnerPriv, "desktop")
	ingestPut(t, st, desk, kcrypto.NewItemID(), nil, record.Plain{Name: "fake", Value: "fake-value"})
	if _, err := st.RevokeDevice(keys.OwnerPriv, desk.Dev, "lost"); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		change    func(*checkpoint.Checkpoint)
		signer    *Identity
		key       string
		malformed bool
		want      error
		skip      bool
	}{
		{name: "valid"},
		{name: "malformed", malformed: true, want: ErrBadSignature},
		{name: "wrong owner", change: func(c *checkpoint.Checkpoint) { c.Dev = phone.Dev }, want: ErrBadSignature},
		{name: "wrong vault", change: func(c *checkpoint.Checkpoint) { c.Vault = kcrypto.NewVaultID() }, want: ErrBadSignature},
		{name: "bad signature", signer: phone, want: ErrBadSignature},
		{name: "nonmember", signer: NewIdentity("unknown"), key: "unknown", want: ErrUnknownDevice},
		{name: "hidden members", change: func(c *checkpoint.Checkpoint) { c.MembersN++ }, want: ErrHidden},
		{name: "hidden log", change: func(c *checkpoint.Checkpoint) { c.Seen[st.ID.Dev] = st.v.lastSeq(st.ID.Dev) + 1 }, want: ErrHidden},
		{name: "revoked clamp", change: func(c *checkpoint.Checkpoint) { c.Seen[desk.Dev] = 100 }},
		{name: "unknown seen ignored", change: func(c *checkpoint.Checkpoint) { c.Seen[NewIdentity("unknown").Dev] = 100 }},
		{name: "revoked skipped", signer: desk, key: "signer", skip: true},
		{name: "approver skipped", signer: phone, key: "signer", skip: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := tt.signer
			if signer == nil {
				signer = st.ID
			}
			dev := st.ID.Dev
			if tt.key != "" {
				dev = signer.Dev
			}
			cp := &checkpoint.Checkpoint{V: 1, Vault: st.Vault(), Dev: dev, MembersN: st.Members().Count, Seen: map[string]uint64{}}
			if tt.change != nil {
				tt.change(cp)
			}
			if tt.skip {
				cp.MembersN += 100
			}
			b := checkpointBytes(t, cp, signer)
			if tt.malformed {
				b = []byte("{")
			}
			out, err := verifyCheckpoints(st.v, map[string][]byte{dev: b})
			requireError(t, err, tt.want)
			if err == nil {
				want := 1
				if tt.skip {
					want = 0
				}
				if len(out) != want {
					t.Fatalf("checkpoints=%d want %d", len(out), want)
				}
				if !tt.skip && !reflect.DeepEqual(out[dev], cp) {
					t.Fatalf("checkpoint changed: %+v", out[dev])
				}
			}
		})
	}
	out, err := verifyCheckpoints(st.v, nil)
	if err != nil || len(out) != 0 {
		t.Fatalf("empty: %v %v", out, err)
	}
}

func TestRecoverSnapshot(t *testing.T) {
	st, keys, _ := newApproverFixture(t)
	r, err := st.Put("", record.Plain{Name: "fake", Value: "fake-recovery-secret"})
	if err != nil {
		t.Fatal(err)
	}
	snap := fullSnapshot(st)
	other, err := recovery.NewSetup(st.Vault(), "another fake password", low)
	if err != nil {
		t.Fatal(err)
	}
	badPriv := *keys
	badPriv.RecoveryPriv = other.Keys.RecoveryPriv
	tests := []struct {
		name string
		keys *recovery.Keys
		pin  string
		snap transport.Snapshot
		want error
	}{
		{"wrong keys", other.Keys, "", snap, ErrWrongKeys},
		{"unwrap failure", &badPriv, "", snap, ErrWrongKeys},
		{"bad pin", keys, "wrong", snap, ErrPin},
		{"broken chain", keys, "", transport.Snapshot{Members: [][]byte{[]byte("{")}}, ErrBrokenChain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Recover(filepath.Join(t.TempDir(), "kg"), NewIdentity("new"), tt.keys, tt.snap, tt.pin)
			requireError(t, err, tt.want)
		})
	}
	if _, err := Recover(st.Home, NewIdentity("new"), keys, snap, ""); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	if _, err := Recover(filepath.Join(t.TempDir(), "kg"), NewIdentity("new"), keys, transport.Snapshot{}, ""); err == nil {
		t.Fatal("empty vault accepted")
	}
	for _, pin := range []string{"", st.GenesisPin()} {
		t.Run("success/"+pin, func(t *testing.T) {
			id := NewIdentity("recovered")
			home := filepath.Join(t.TempDir(), "kg")
			got, err := Recover(home, id, keys, snap, pin)
			if err != nil {
				t.Fatal(err)
			}
			if d := got.Members().Devices[id.Dev]; d == nil || d.Revoked {
				t.Fatal("new device not registered")
			}
			got.Close()
			got, err = Open(home, id)
			if err != nil {
				t.Fatal(err)
			}
			defer got.Close()
			p, _, err := got.Get(r.Item)
			if err != nil || p.Value != "fake-recovery-secret" {
				t.Fatalf("readback: %+v %v", p, err)
			}
		})
	}
	t.Run("ingest cleanup", func(t *testing.T) {
		bad := fullSnapshot(st)
		bad.Logs[st.ID.Dev] = [][]byte{[]byte("{")}
		home := filepath.Join(t.TempDir(), "kg")
		_, err := Recover(home, NewIdentity("new"), keys, bad, "")
		requireError(t, err, ErrBadSignature)
		requireCleanHome(t, home)
	})
	t.Run("registration cleanup", func(t *testing.T) {
		home := filepath.Join(t.TempDir(), "kg")
		_, err := Recover(home, st.ID, keys, snap, "")
		if err == nil {
			t.Fatal("duplicate registration accepted")
		}
		requireCleanHome(t, home)
	})
}

func TestJoinSnapshot(t *testing.T) {
	st, keys, _ := newApproverFixture(t)
	id := addKeyHolder(t, st, keys.OwnerPriv, "joiner")
	r, err := st.Put("", record.Plain{Name: "fake", Value: "fake-join-secret"})
	if err != nil {
		t.Fatal(err)
	}
	snap := fullSnapshot(st)
	for _, tt := range []struct {
		name, pin string
		id        *Identity
		want      error
	}{
		{"missing pin", "", id, ErrPin}, {"wrong pin", "wrong", id, ErrPin}, {"absent", st.GenesisPin(), NewIdentity("absent"), ErrNotMember},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Join(filepath.Join(t.TempDir(), "kg"), tt.id, snap, tt.pin)
			requireError(t, err, tt.want)
		})
	}
	_, err = Join(st.Home, id, snap, st.GenesisPin())
	requireError(t, err, ErrExists)
	_, err = Join(filepath.Join(t.TempDir(), "kg"), id, transport.Snapshot{Members: [][]byte{[]byte("{")}}, st.GenesisPin())
	requireError(t, err, ErrBrokenChain)
	got, err := Join(filepath.Join(t.TempDir(), "kg"), id, snap, st.GenesisPin())
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := got.Get(r.Item)
	got.Close()
	if err != nil || p.Value != "fake-join-secret" {
		t.Fatalf("readback: %+v %v", p, err)
	}
	if _, err := st.RevokeDevice(keys.OwnerPriv, id.Dev, "lost"); err != nil {
		t.Fatal(err)
	}
	_, err = Join(filepath.Join(t.TempDir(), "kg"), id, fullSnapshot(st), st.GenesisPin())
	requireError(t, err, ErrNotMember)
}

func TestBootstrapCleanup(t *testing.T) {
	st, _, _ := newApproverFixture(t)
	for _, stage := range []string{"mkdir", "config", "local", "open", "ingest"} {
		t.Run(stage, func(t *testing.T) {
			home := t.TempDir()
			snap := fullSnapshot(st)
			switch stage {
			case "mkdir":
				home = filepath.Join(home, "file")
				if err := os.WriteFile(home, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "config":
				if err := os.Mkdir(vaultPath(home), 0700); err != nil {
					t.Fatal(err)
				}
			case "local":
				if err := os.WriteFile(filepath.Join(home, "state"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "open":
				if err := os.Mkdir(membersPath(home), 0700); err != nil {
					t.Fatal(err)
				}
			case "ingest":
				snap.Logs[st.ID.Dev] = [][]byte{[]byte("{")}
			}
			if _, err := bootstrap(home, NewIdentity("bootstrap"), st.Members(), snap); err == nil {
				t.Fatal("expected failure")
			}
			if stage != "mkdir" {
				requireCleanHome(t, home)
			}
		})
	}
}

func TestChannelStateAndCursors(t *testing.T) {
	st, _, _ := newApproverFixture(t)
	for i := 0; i < 2; i++ {
		if _, err := st.Put("", record.Plain{Name: "fake", Value: "fake-value"}); err != nil {
			t.Fatal(err)
		}
	}
	count := st.Members().Count
	if m, hw := st.cursor("unknown"); m != 0 || hw != nil {
		t.Fatalf("unknown cursor %d %v", m, hw)
	}
	if got := st.Since("new"); got.Members != 0 || len(got.Logs) != 0 {
		t.Fatalf("new since %+v", got)
	}
	if first, lines := st.PendingMembers("new"); first != 0 || len(lines) != int(count) {
		t.Fatalf("pending members %d %d", first, len(lines))
	}
	if first, lines := st.PendingOwnLines("new"); first != 1 || len(lines) != 2 {
		t.Fatalf("pending logs %d %d", first, len(lines))
	}
	if err := st.MarkPushed("invalid!", 0, 0); err == nil {
		t.Fatal("invalid channel accepted")
	}
	if err := st.MarkPushed("relay", 3, count); err == nil {
		t.Fatal("sequence beyond local accepted")
	}
	if err := st.MarkPushed("relay", 0, count+1); err == nil {
		t.Fatal("members beyond local accepted")
	}
	if err := st.MarkPushed("relay", 2, count); err != nil {
		t.Fatal(err)
	}
	if err := st.bump("relay", count-1, map[string]uint64{st.ID.Dev: 1}); err != nil {
		t.Fatal(err)
	}
	if err := st.bump("relay", 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.bump("mirror", count-1, map[string]uint64{st.ID.Dev: 1}); err != nil {
		t.Fatal(err)
	}
	if m, hw := st.cursor("mirror"); m != count-1 || hw[st.ID.Dev] != 1 {
		t.Fatalf("independent cursor %d %v", m, hw)
	}
	if first, lines := st.PendingOwnLines("mirror"); first != 2 || len(lines) != 1 || !reflect.DeepEqual(lines[0], st.v.logs[st.ID.Dev].lines[1]) {
		t.Fatalf("partially pushed log %d %q", first, lines)
	}
	if first, lines := st.PendingMembers("mirror"); first != int(count-1) || len(lines) != 1 || !reflect.DeepEqual(lines[0], st.v.mlines[count-1]) {
		t.Fatalf("partially pushed members %d %q", first, lines)
	}
	for _, ch := range []string{"", "relay"} {
		m, hw := st.cursor(ch)
		if m != count || hw[st.ID.Dev] != 2 {
			t.Fatalf("%s cursor %d %v", ch, m, hw)
		}
		since := st.Since(ch)
		if since.Members != int(count-1) || since.Logs[st.ID.Dev] != 1 {
			t.Fatalf("since %+v", since)
		}
		if first, lines := st.PendingMembers(ch); first != int(count) || len(lines) != 0 {
			t.Fatalf("pending members %d %d", first, len(lines))
		}
		if first, lines := st.PendingOwnLines(ch); first != 3 || len(lines) != 0 {
			t.Fatalf("pending logs %d %d", first, len(lines))
		}
	}
	home, id := st.Home, st.ID
	st.Close()
	reopened, err := Open(home, id)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if m, hw := reopened.cursor("mirror"); m != count-1 || hw[id.Dev] != 1 {
		t.Fatalf("reopened independent cursor %d %v", m, hw)
	}
	for _, ch := range []string{"", "relay"} {
		m, hw := reopened.cursor(ch)
		if m != count || hw[id.Dev] != 2 {
			t.Fatalf("reopened %s: %d %v", ch, m, hw)
		}
	}
	empty, _, _ := newApproverFixture(t)
	if first, lines := empty.PendingOwnLines("new"); first != 1 || len(lines) != 0 {
		t.Fatalf("empty pending %d %d", first, len(lines))
	}
}

func TestLoadChannels(t *testing.T) {
	for _, kind := range []string{"json", "version", "channel", "nil map", "MAC", "valid", "skip", "read directory", "read file"} {
		t.Run(kind, func(t *testing.T) {
			st, _, _ := newApproverFixture(t)
			path := chanPath(st.Home, "relay")
			cf := chanFile{V: 1, Channel: "relay", MembersN: st.Members().Count, HW: map[string]uint64{st.ID.Dev: 0}}
			cf.MAC = st.sign(st.macInput("channel", "relay", cf.MembersN, cf.HW))
			switch kind {
			case "version":
				cf.V = 2
			case "channel":
				cf.Channel = "other"
			case "nil map":
				cf.HW = nil
			case "MAC":
				cf.MembersN++
			}
			if err := writeJSON(path, cf); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "json":
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "skip":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"BAD.json", ".json", "relay.txt", "a.b.json"} {
					if err := os.WriteFile(filepath.Join(filepath.Dir(path), name), []byte("{"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "read directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Dir(path), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "read file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			err := st.loadChannels()
			switch kind {
			case "valid":
				if err != nil {
					t.Fatal(err)
				}
				if got := st.chans["relay"]; got == nil || got.MembersN != cf.MembersN || !reflect.DeepEqual(got.HW, cf.HW) {
					t.Fatalf("loaded %+v", got)
				}
			case "skip":
				if err != nil || len(st.chans) != 0 {
					t.Fatalf("skip: %v %v", st.chans, err)
				}
			case "read directory", "read file":
				if err == nil {
					t.Fatal("expected IO failure")
				}
			default:
				requireError(t, err, ErrLocalState)
			}
		})
	}
}

func TestBumpPersistenceErrors(t *testing.T) {
	for _, ch := range []string{"", "relay"} {
		t.Run("channel/"+ch, func(t *testing.T) {
			st, _, _ := newApproverFixture(t)
			path := localPath(st.Home)
			if ch != "" {
				path = chanPath(st.Home, ch)
			}
			if ch == "" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := st.bump(ch, st.Members().Count, nil); err == nil {
				t.Fatal("expected persistence failure")
			}
		})
	}
}
