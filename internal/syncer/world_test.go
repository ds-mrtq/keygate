package syncer

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"keygate/internal/kcrypto"
	"keygate/internal/recovery"
	"keygate/internal/store"
	"keygate/internal/transport"
)

// fake is an in-memory untrusted channel. Tests mutate its maps directly to attack.
type fake struct {
	mu      sync.Mutex
	name    string
	Hide    map[string]map[uint64]bool // lines Pull pretends not to have (PushLog still says ErrExists)
	Members map[int][]byte
	Logs    map[string]map[uint64][]byte
	CPs     map[string][]byte
}

func newFake(name string) *fake {
	return &fake{name: name, Members: map[int][]byte{}, Logs: map[string]map[uint64][]byte{}, CPs: map[string][]byte{}}
}

func (f *fake) Name() string { return f.name }

func (f *fake) Pull(_ context.Context, since transport.Since) (transport.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	snap := transport.Snapshot{Logs: map[string][][]byte{}, Checkpoints: map[string][]byte{}}
	ns := make([]int, 0, len(f.Members))
	for n := range f.Members {
		if n >= since.Members {
			ns = append(ns, n)
		}
	}
	sort.Ints(ns)
	for _, n := range ns {
		snap.Members = append(snap.Members, f.Members[n])
	}
	for dev, m := range f.Logs {
		seqs := make([]uint64, 0, len(m))
		for q := range m {
			if q > since.Logs[dev] {
				seqs = append(seqs, q)
			}
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		for _, q := range seqs {
			if !f.Hide[dev][q] {
				snap.Logs[dev] = append(snap.Logs[dev], m[q])
			}
		}
	}
	for d, b := range f.CPs {
		snap.Checkpoints[d] = b
	}
	return snap, nil
}

func (f *fake) PushLog(_ context.Context, dev string, seq uint64, line []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Logs[dev] == nil {
		f.Logs[dev] = map[uint64][]byte{}
	}
	if _, ok := f.Logs[dev][seq]; ok {
		return transport.ErrExists
	}
	f.Logs[dev][seq] = append([]byte(nil), line...)
	return nil
}

func (f *fake) PushMember(_ context.Context, n int, line []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.Members[n]; ok {
		return transport.ErrExists
	}
	f.Members[n] = append([]byte(nil), line...)
	return nil
}

func (f *fake) PushCheckpoint(_ context.Context, dev string, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.CPs[dev] = append([]byte(nil), body...)
	return nil
}

var lowArgon = kcrypto.Argon2Params{T: 1, M: 64, P: 1}

const testPwd = "correct horse battery staple"

type device struct {
	st *store.Store
	sy *Syncer
}

type world struct {
	t     *testing.T
	ctx   context.Context
	ch    *fake
	setup *recovery.Setup
	vault string
	a     *device
}

func (w *world) sync(d *device) error {
	_, err := d.sy.Sync(w.ctx)
	return err
}

func (w *world) mustSync(d *device) {
	w.t.Helper()
	if err := w.sync(d); err != nil {
		w.t.Fatalf("sync: %v", err)
	}
}

// newWorld creates vault + device A on a fresh fake channel and syncs A once.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, ctx: context.Background(), ch: newFake("fake"), vault: kcrypto.NewVaultID()}
	setup, err := recovery.NewSetup(w.vault, testPwd, lowArgon)
	if err != nil {
		t.Fatal(err)
	}
	w.setup = setup
	id := store.NewIdentity("laptop-a")
	st, err := store.Init(filepath.Join(t.TempDir(), "a"), w.vault, id, setup.Keys, setup.Salt, setup.Params, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	w.a = &device{st: st, sy: &Syncer{Store: st, T: w.ch}}
	w.mustSync(w.a)
	return w
}

// addDevice: owner (via A) adds a new device, A syncs, the new device joins from the channel.
func (w *world) addDevice(label string) *device {
	w.t.Helper()
	id := store.NewIdentity(label)
	if err := w.a.st.AddDevice(w.setup.Keys.OwnerPriv, id.Public()); err != nil {
		w.t.Fatal(err)
	}
	w.mustSync(w.a)
	snap, _ := w.ch.Pull(w.ctx, transport.Since{})
	st, err := store.Join(filepath.Join(w.t.TempDir(), label), id, snap, w.a.st.GenesisPin())
	if err != nil {
		w.t.Fatal(err)
	}
	d := &device{st: st, sy: &Syncer{Store: st, T: w.ch}}
	w.mustSync(d)
	return d
}

func put(t *testing.T, d *device, item, name, value string) string {
	t.Helper()
	r, err := d.st.Put(item, plain(name, value))
	if err != nil {
		t.Fatal(err)
	}
	return r.Item
}
