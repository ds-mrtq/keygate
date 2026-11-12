package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"keygate/internal/api"
	"keygate/internal/approve"
	"keygate/internal/audit"
	"keygate/internal/broker/wire"
	"keygate/internal/brokerclient"
	"keygate/internal/members"
	"keygate/internal/remote"
	"keygate/internal/store"
	"keygate/internal/transport/relay"
)

// fakeMail is the relay in memory: the broker's mailbox and the phone's inbox in one.
type fakeMail struct {
	mu     sync.Mutex
	msgs   []relay.Msg
	views  map[string][]byte
	pushes int
	puts   int
}

func (m *fakeMail) PutView(_ context.Context, to string, body []byte, push bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.views == nil {
		m.views = map[string][]byte{}
	}
	m.views[to] = append([]byte(nil), body...)
	m.puts++
	if push {
		m.pushes++
	}
	return nil
}

func (m *fakeMail) GetMsgs(context.Context) ([]relay.Msg, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]relay.Msg(nil), m.msgs...), nil
}

func (m *fakeMail) DeleteMsg(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, x := range m.msgs {
		if x.ID == id {
			m.msgs = append(m.msgs[:i], m.msgs[i+1:]...)
			break
		}
	}
	return nil
}

func (m *fakeMail) latest(to string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.views[to]
}

func (m *fakeMail) counts() (puts, pushes int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.puts, m.pushes
}

func (m *fakeMail) push(msg relay.Msg) {
	m.mu.Lock()
	m.msgs = append(m.msgs, msg)
	m.mu.Unlock()
}

// rfix is a broker fixture with a mailbox and one paired approver (the "phone").
type rfix struct {
	*fixture
	mail  *fakeMail
	phone *store.Identity
	seen  [][]byte // every decrypted view, to search for leaked values
}

type rcfg struct {
	noApprover bool // do not pair the phone
	mod        func(*Config)
}

func newRemoteFix(t *testing.T, o rcfg) *rfix {
	t.Helper()
	mail := &fakeMail{}
	f := newFixtureWith(t, 0, time.Hour, func(c *Config) {
		c.LockOnScreenLock = false
		c.Mailbox = func(store.VaultConfig, *store.Identity) Mailbox { return mail }
		c.RemoteFast, c.RemoteSlow, c.RemoteMinPost, c.RemoteBeat = 15*time.Millisecond, 15*time.Millisecond, 5*time.Millisecond, 150*time.Millisecond
		c.RemoteDelay = 400 * time.Millisecond
		c.ApprovalWait = 10 * time.Second
		if o.mod != nil {
			o.mod(c)
		}
	})
	r := &rfix{fixture: f, mail: mail}
	if !o.noApprover {
		r.pair()
		if err := f.b.Unlock(context.Background()); err != nil { // refresh the approver list from the verified store
			t.Fatal(err)
		}
		f.b.endSession("test")
	}
	return r
}

// pair adds the phone as an approver device while the broker is locked.
func (r *rfix) pair() {
	r.t.Helper()
	phone := store.NewIdentity("phone")
	body := phone.Public()
	body.Role = members.RoleApprover
	r.withStore(func(st *store.Store) {
		if err := st.AddDevice(r.keys.OwnerPriv, body); err != nil {
			r.t.Fatal(err)
		}
	})
	r.phone = phone
}

func (r *rfix) senderKey(dev string) ed25519.PublicKey {
	if dev == r.b.id.Dev {
		return r.b.id.EdPub
	}
	return nil
}

func (r *rfix) view() (remote.View, bool) {
	line := r.mail.latest(r.phone.Dev)
	if line == nil {
		return remote.View{}, false
	}
	_, _, _, pt, err := remote.Open(r.b.vaultID, r.phone.Dev, r.phone.XPriv, line, r.senderKey)
	if err != nil {
		r.t.Fatalf("phone cannot open the view: %v", err)
	}
	r.seen = append(r.seen, pt)
	var v remote.View
	if err := json.Unmarshal(pt, &v); err != nil {
		r.t.Fatal(err)
	}
	return v, true
}

func (r *rfix) waitView(what string, pred func(v remote.View) bool) remote.View {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := r.view(); ok && pred(v) {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatalf("timeout waiting for view: %s", what)
	return remote.View{}
}

func (r *rfix) waitPending() remote.Pending {
	r.t.Helper()
	v := r.waitView("a pending request", func(v remote.View) bool { return len(v.Pending) > 0 })
	return v.Pending[0]
}

func (r *rfix) noPendingFor(d time.Duration) {
	r.t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if v, ok := r.view(); ok && len(v.Pending) > 0 {
			r.t.Fatalf("unexpected pending request: %+v", v.Pending[0])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// sendAs posts a message signed by id with the given time.
func (r *rfix) sendAs(id *store.Identity, v any, at time.Time) {
	r.t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		r.t.Fatal(err)
	}
	line, err := remote.Seal(r.b.vaultID, id, r.b.id.Dev, r.b.id.XPub, raw, at)
	if err != nil {
		r.t.Fatal(err)
	}
	var env struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(line, &env); err != nil {
		r.t.Fatal(err)
	}
	r.mail.push(relay.Msg{ID: env.ID, From: id.Dev, Body: line})
}

// send posts a message from the phone, now.
func (r *rfix) send(v any) { r.t.Helper(); r.sendAs(r.phone, v, time.Now()) }

func decision(p remote.Pending, choice string) remote.Decision {
	return remote.Decision{Kind: remote.KindDecision, RID: p.RID, Digest: p.Digest(), Choice: choice}
}

func (r *rfix) command(boot int64, op, args string) string {
	cid := remote.NewID()
	if args == "" {
		args = "{}"
	}
	r.send(remote.Command{Kind: remote.KindCommand, CID: cid, Boot: boot, Op: op, Args: json.RawMessage(args)})
	return cid
}

func (r *rfix) result(cid string) remote.CmdResult {
	r.t.Helper()
	var res remote.CmdResult
	r.waitView("result of command", func(v remote.View) bool {
		for _, x := range v.Results {
			if x.CID == cid {
				res = x
				return true
			}
		}
		return false
	})
	return res
}

type runOut struct {
	code int
	err  error
	out  string
}

// runAsync runs req through a client that records the broker's notes.
func (r *rfix) runAsync(req api.RunRequest) (<-chan runOut, *[]string) {
	cli := brokerclient.New(SockPath(r.home))
	var mu sync.Mutex
	var notes []string
	cli.Note = func(m string) { mu.Lock(); notes = append(notes, m); mu.Unlock() }
	ch := make(chan runOut, 1)
	go func() {
		var out bytes.Buffer
		code, err := cli.Run(context.Background(), req, &out, &out)
		ch <- runOut{code, err, out.String()}
	}()
	return ch, &notes
}

func (r *rfix) await(ch <-chan runOut) runOut {
	r.t.Helper()
	select {
	case o := <-ch:
		return o
	case <-time.After(15 * time.Second):
		r.t.Fatal("timeout waiting for the client")
	}
	return runOut{}
}

func (r *rfix) stillBlocked(ch <-chan runOut, d time.Duration) {
	r.t.Helper()
	select {
	case o := <-ch:
		r.t.Fatalf("client returned early: %+v", o)
	case <-time.After(d):
	}
}

// engineIdle asserts that no request is open and no unused decision is kept.
func (r *rfix) engineIdle() {
	r.t.Helper()
	r.b.rmu.Lock()
	defer r.b.rmu.Unlock()
	if len(r.b.pending) != 0 || len(r.b.preapproved) != 0 {
		r.t.Fatalf("engine not idle: %d open, %d unused decisions", len(r.b.pending), len(r.b.preapproved))
	}
}

func ledger(t *testing.T, f *fixture) []audit.Entry {
	t.Helper()
	data, _ := os.ReadFile(filepath.Join(f.home, "audit", "ledger.jsonl"))
	var out []audit.Entry
	for _, l := range bytes.Split(data, []byte("\n")) {
		var e audit.Entry
		if json.Unmarshal(l, &e) == nil && e.Event != "" {
			out = append(out, e)
		}
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// (1) locked screen + allow from the phone: the run proceeds, audit and the stored grant name the phone.
func TestRemoteAllowOnLockedScreen(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	req := helperRun(t, r.fixture, "")
	r.locked.Store(true)
	n := r.approvals.Load()
	ch, notes := r.runAsync(req)
	p := r.waitPending()
	if p.Op != "grant" || len(p.Secrets) != 1 || p.Secrets[0] != "ebs/test/tok" || !contains(p.Choices, "session") {
		t.Fatalf("pending %+v", p)
	}
	r.send(decision(p, "allow"))
	o := r.await(ch)
	if o.err != nil || o.code != 0 {
		t.Fatalf("run: %+v", o)
	}
	if r.approvals.Load() != n {
		t.Fatal("Hello must not be asked on a locked screen")
	}
	if len(*notes) == 0 || !strings.Contains((*notes)[0], "đang chờ duyệt trên điện thoại") {
		t.Fatalf("notes %v", *notes)
	}
	by := "remote:" + r.phone.Dev
	var sawGrant bool
	for _, e := range ledger(t, r.fixture) {
		if e.Event == audit.EvGrant && e.Approval == by {
			sawGrant = true
		}
	}
	if !sawGrant {
		t.Fatalf("audit lacks a grant with approval=%s: %+v", by, ledger(t, r.fixture))
	}
	gs, err := r.cli.Grants(context.Background())
	if err != nil || len(gs) != 1 || gs[0].By != by || !gs[0].Durable {
		t.Fatalf("grants %+v %v", gs, err)
	}
	r.mustRun(req) // remembered: nobody is asked again
}

// (2) deny from the phone.
func TestRemoteDeny(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	req := helperRun(t, r.fixture, "")
	r.locked.Store(true)
	ch, _ := r.runAsync(req)
	p := r.waitPending()
	r.send(decision(p, "deny"))
	o := r.await(ch)
	if code(o.err) != wire.CodeDenied {
		t.Fatalf("want denied, got %+v", o)
	}
	var sawDeny bool
	for _, e := range ledger(t, r.fixture) {
		sawDeny = sawDeny || (e.Event == audit.EvDeny && e.Approval == "remote:"+r.phone.Dev)
	}
	if !sawDeny {
		t.Fatalf("audit lacks the remote deny: %+v", ledger(t, r.fixture))
	}
	r.noPendingFor(100 * time.Millisecond)
}

// (3) ApprovalWait elapses: pending (exit 75), the decision that arrives later still counts, and the
// re-run neither opens a new request nor asks anybody.
func TestRemotePendingThenAllowThenRerun(t *testing.T) {
	r := newRemoteFix(t, rcfg{mod: func(c *Config) { c.ApprovalWait = 400 * time.Millisecond }})
	req := helperRun(t, r.fixture, "")
	r.locked.Store(true)
	n := r.approvals.Load()
	ch, _ := r.runAsync(req)
	p := r.waitPending()
	o := r.await(ch)
	if code(o.err) != wire.CodePending {
		t.Fatalf("want pending, got %+v", o)
	}
	if !strings.Contains(o.err.Error(), p.RID[:6]) {
		t.Fatalf("message must name the request %s: %v", p.RID[:6], o.err)
	}
	if v := r.waitView("request still listed", func(v remote.View) bool { return len(v.Pending) == 1 }); v.Pending[0].RID != p.RID {
		t.Fatal("request changed")
	}
	r.send(decision(p, "allow"))
	r.waitView("request closed", func(v remote.View) bool { return len(v.Pending) == 0 })
	ch2, _ := r.runAsync(req)
	o = r.await(ch2)
	if o.err != nil || o.code != 0 {
		t.Fatalf("re-run: %+v", o)
	}
	if r.approvals.Load() != n {
		t.Fatal("nobody should have been asked again")
	}
	r.noPendingFor(100 * time.Millisecond)
	r.engineIdle()
}

// (4) a decision with a wrong digest is dropped; the right one still works.
func TestRemoteWrongDigestDropped(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	req := helperRun(t, r.fixture, "")
	r.locked.Store(true)
	ch, _ := r.runAsync(req)
	p := r.waitPending()
	bad := decision(p, "allow")
	bad.Digest = "sha256:" + strings.Repeat("0", 64)
	r.send(bad)
	r.stillBlocked(ch, 300*time.Millisecond)
	if v, _ := r.view(); len(v.Pending) != 1 {
		t.Fatal("request must stay open")
	}
	r.send(decision(p, "allow"))
	if o := r.await(ch); o.err != nil || o.code != 0 {
		t.Fatalf("run: %+v", o)
	}
}

// (5) a message signed by a full (key-holding) device is not an approver message.
func TestRemoteNonApproverSenderDropped(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	full := store.NewIdentity("other-laptop")
	r.withStore(func(st *store.Store) {
		if err := st.AddDevice(r.keys.OwnerPriv, full.Public()); err != nil {
			t.Fatal(err)
		}
	})
	if err := r.b.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.b.endSession("test")
	req := helperRun(t, r.fixture, "")
	r.locked.Store(true)
	ch, _ := r.runAsync(req)
	p := r.waitPending()
	r.sendAs(full, decision(p, "allow"), time.Now())
	r.stillBlocked(ch, 300*time.Millisecond)
	r.send(decision(p, "allow")) // the genuine approver still decides
	if o := r.await(ch); o.err != nil || o.code != 0 {
		t.Fatalf("run: %+v", o)
	}
}

// (6) old messages, messages from before the broker started and commands for another boot are dropped.
func TestRemoteReplayAndStaleDropped(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	req := helperRun(t, r.fixture, "")
	r.locked.Store(true)
	ch, _ := r.runAsync(req)
	p := r.waitPending()
	boot := r.b.started.UnixMilli()
	r.sendAs(r.phone, decision(p, "allow"), time.Now().Add(-11*time.Minute)) // older than MaxMsgAge
	r.sendAs(r.phone, decision(p, "allow"), r.b.started.Add(-2*time.Second)) // before this broker started
	r.sendAs(r.phone, decision(p, "allow"), time.Now().Add(10*time.Minute))  // far in the future
	r.sendAs(r.phone, remote.Command{Kind: remote.KindCommand, CID: remote.NewID(), Boot: boot - 1, Op: "lock", Args: json.RawMessage(`{}`)}, time.Now())
	r.stillBlocked(ch, 400*time.Millisecond)
	if r.b.Locked() {
		t.Fatal("a command for another boot must not lock")
	}
	if v, _ := r.view(); len(v.Pending) != 1 {
		t.Fatal("request must stay open")
	}
	r.send(decision(p, "allow"))
	if o := r.await(ch); o.err != nil || o.code != 0 {
		t.Fatalf("run: %+v", o)
	}
}

// (7) locked vault + a phone decision "allow and open a work session" on the unlock request.
func TestRemoteUnlockWithSession(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	r.b.Lock()
	r.locked.Store(true)
	errc := make(chan error, 1)
	go func() { errc <- brokerclient.New(SockPath(r.home)).SessionStart(context.Background()) }()
	p := r.waitPending()
	if p.Op != "unlock" || !contains(p.Choices, "session") {
		t.Fatalf("a locked vault asks to unlock first: %+v", p)
	}
	r.send(decision(p, "session"))
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("session start: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
	if r.b.Locked() || !r.b.SessionOpen() {
		t.Fatalf("locked=%v session=%v", r.b.Locked(), r.b.SessionOpen())
	}
}

// (7b) nobody waits for the unlock any more: the phone decision itself unlocks and opens the session.
func TestRemoteUnlockDecisionAfterCallerLeft(t *testing.T) {
	r := newRemoteFix(t, rcfg{mod: func(c *Config) { c.ApprovalWait = 300 * time.Millisecond }})
	r.b.Lock()
	r.locked.Store(true)
	_, err := r.cli.List(context.Background())
	if code(err) != wire.CodePending {
		t.Fatalf("want pending, got %v", err)
	}
	p := r.waitPending()
	r.send(decision(p, "session"))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !(r.b.SessionOpen() && !r.b.Locked()) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.b.Locked() || !r.b.SessionOpen() {
		t.Fatalf("locked=%v session=%v", r.b.Locked(), r.b.SessionOpen())
	}
}

// (8) grant-revoke, lock, session-start from a locked vault, session-end commands.
func TestRemoteCommands(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	req := helperRun(t, r.fixture, "")
	r.mustRun(req) // Hello grant (screen unlocked)
	v := r.waitView("grant listed", func(v remote.View) bool { return len(v.Grants) == 1 })
	boot := v.Boot
	if res := r.result(r.command(boot, "grant-revoke", `{"secret":"ebs/test/tok"}`)); !res.OK {
		t.Fatalf("revoke: %+v", res)
	}
	if gs, _ := r.cli.Grants(context.Background()); len(gs) != 0 {
		t.Fatalf("grants after revoke: %+v", gs)
	}
	if res := r.result(r.command(boot, "lock", "")); !res.OK {
		t.Fatalf("lock: %+v", res)
	}
	if !r.b.Locked() {
		t.Fatal("not locked")
	}
	r.waitView("view says locked", func(v remote.View) bool { return !v.Unlocked && len(v.Secrets) == 0 })
	if res := r.result(r.command(boot, "session-start", "")); !res.OK {
		t.Fatalf("session-start: %+v", res)
	}
	if r.b.Locked() || !r.b.SessionOpen() {
		t.Fatalf("locked=%v session=%v", r.b.Locked(), r.b.SessionOpen())
	}
	v = r.waitView("view shows the session", func(v remote.View) bool { return v.Session != nil && v.Unlocked })
	if len(v.Secrets) == 0 {
		t.Fatal("unlocked view must list secret names")
	}
	if res := r.result(r.command(boot, "session-end", "")); !res.OK || r.b.SessionOpen() {
		t.Fatalf("session-end: %+v open=%v", res, r.b.SessionOpen())
	}
	var sawRevoke bool
	for _, e := range ledger(t, r.fixture) {
		sawRevoke = sawRevoke || (e.Event == audit.EvGrantRevoke && e.Peer == "remote:"+r.phone.Dev)
	}
	if !sawRevoke {
		t.Fatalf("audit lacks the revoke: %+v", ledger(t, r.fixture))
	}
}

// (9) a secret added from the phone is stored; its value is in no view, log or audit line.
func TestRemoteSetNeverLeaksValue(t *testing.T) {
	const val, val2 = "v-PHONE-123", "v-OTHER-456"
	r := newRemoteFix(t, rcfg{})
	boot := r.waitView("first view", func(remote.View) bool { return true }).Boot
	set := func(overwrite bool, v string) remote.CmdResult {
		args, _ := json.Marshal(phoneSetArgs{Name: "demo/phone", Kind: "env", Env: "dev", EnvName: "PHONE_TOK", Value: v, Overwrite: overwrite})
		return r.result(r.command(boot, "set", string(args)))
	}
	if res := set(false, val); !res.OK {
		t.Fatalf("set: %+v", res)
	}
	names, err := r.cli.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, n := range names {
		found = found || n.Name == "demo/phone"
	}
	if !found {
		t.Fatalf("secret missing: %+v", names)
	}
	if res := set(false, "ignored"); res.OK || !strings.Contains(res.Msg, "đã tồn tại") {
		t.Fatalf("overwrite without the flag must fail: %+v", res)
	}
	if res := set(true, val2); !res.OK {
		t.Fatalf("overwrite: %+v", res)
	}
	r.waitView("results visible", func(v remote.View) bool { return len(v.Results) >= 3 })
	for _, v := range r.seen {
		for _, secret := range []string{val, val2} {
			if bytes.Contains(v, []byte(secret)) {
				t.Fatalf("a view contains %q", secret)
			}
		}
	}
	data, _ := os.ReadFile(filepath.Join(r.home, "audit", "ledger.jsonl"))
	for _, secret := range []string{val, val2} {
		if bytes.Contains(data, []byte(secret)) || strings.Contains(r.prompt.String(), secret) {
			t.Fatalf("value %q leaked to the audit ledger or the broker log", secret)
		}
	}
}

// gateApprover is Hello that can be made to hang until its context ends.
type gateApprover struct {
	block   atomic.Bool
	calls   atomic.Int32
	started chan struct{}
}

func (g *gateApprover) Approve(ctx context.Context, _ string) error {
	g.calls.Add(1)
	if !g.block.Load() {
		return nil
	}
	select {
	case g.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

// (10) screen open: Hello is asked first and the phone hears nothing before RemoteDelay; a Hello that
// succeeds leaves nothing pending; a phone decision cancels a Hello that is still open.
func TestRemoteLocalFirst(t *testing.T) {
	g := &gateApprover{started: make(chan struct{}, 4)}
	r := newRemoteFix(t, rcfg{mod: func(c *Config) {
		c.Approver = g
		c.RemoteDelay = 700 * time.Millisecond
	}})
	req := helperRun(t, r.fixture, "")
	before := g.calls.Load()
	ch, _ := r.runAsync(req)
	if o := r.await(ch); o.err != nil || o.code != 0 {
		t.Fatalf("run with a working Hello: %+v", o)
	}
	if g.calls.Load() != before+1 {
		t.Fatal("Hello must be asked exactly once")
	}
	r.noPendingFor(150 * time.Millisecond)

	// Hello hangs: nothing on the phone until RemoteDelay, then the request appears.
	if n, err := r.cli.GrantsRevoke(context.Background(), "ebs/test/tok", false); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	g.block.Store(true)
	ch, _ = r.runAsync(req)
	select {
	case <-g.started:
	case <-time.After(5 * time.Second):
		t.Fatal("Hello never asked")
	}
	time.Sleep(150 * time.Millisecond)
	if v, ok := r.view(); ok && len(v.Pending) != 0 {
		t.Fatal("the phone must not hear about it before RemoteDelay")
	}
	p := r.waitPending()
	r.send(decision(p, "allow"))
	if o := r.await(ch); o.err != nil || o.code != 0 {
		t.Fatalf("run after the phone decision: %+v", o)
	}
}

// (11) reveal never goes to the phone: on a locked screen it fails and nothing is published.
func TestRemoteRevealLocalOnly(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	helperRun(t, r.fixture, "")
	r.locked.Store(true)
	err := r.cli.Reveal(context.Background(), "ebs/test/tok")
	if err == nil || !strings.Contains(err.Error(), "không có kênh duyệt") {
		t.Fatalf("reveal: %v", err)
	}
	r.noPendingFor(200 * time.Millisecond)
}

// (12) a decision for one policy.yaml / .env content never applies to another.
func TestRemoteBindRejectsChangedContent(t *testing.T) {
	r := newRemoteFix(t, rcfg{mod: func(c *Config) { c.ApprovalWait = 300 * time.Millisecond }})
	helperRun(t, r.fixture, "")
	r.locked.Store(true)
	ctx := context.Background()

	pol := func(extra string) { r.policy(basePolicy+extra, false) }
	oldPin, _ := os.ReadFile(filepath.Join(r.home, "state", "policy.pin"))
	pol("  more/*:\n    allow_commands: [\"sql /@A\"]\n    approval: user-presence\n")
	_, err := r.cli.PolicyApply(ctx)
	if code(err) != wire.CodePending {
		t.Fatalf("want pending, got %v", err)
	}
	p1 := r.waitPending()
	if p1.Op != "policy" || !strings.Contains(p1.Detail, "more/*") || !strings.HasPrefix(p1.Bind, "sha256:") {
		t.Fatalf("pending %+v", p1)
	}
	r.send(decision(p1, "allow"))
	r.waitView("closed", func(v remote.View) bool { return len(v.Pending) == 0 })
	pol("  other/*:\n    allow_commands: [\"sql /@B\"]\n    approval: user-presence\n") // edited after the approval
	if _, err := r.cli.PolicyApply(ctx); code(err) != wire.CodePending {
		t.Fatalf("an approval for other content must not be used: %v", err)
	}
	p2 := r.waitPending()
	if p2.RID == p1.RID || p2.Bind == p1.Bind {
		t.Fatalf("expected a fresh request: %+v vs %+v", p1, p2)
	}
	if pin, _ := os.ReadFile(filepath.Join(r.home, "state", "policy.pin")); !bytes.Equal(pin, oldPin) {
		t.Fatal("policy was applied without a matching approval")
	}
	r.send(decision(p2, "allow"))
	r.waitView("closed again", func(v remote.View) bool { return len(v.Pending) == 0 })
	if _, err := r.cli.PolicyApply(ctx); err != nil {
		t.Fatalf("the approved content applies: %v", err)
	}

	// import: same rule
	env := filepath.Join(t.TempDir(), "x.env")
	os.WriteFile(env, []byte("A_KEY=one\n"), 0o600)
	if _, err := r.cli.Import(ctx, wire.ImportArgs{Dotenv: env, Prefix: "imp/"}); code(err) != wire.CodePending {
		t.Fatalf("import: %v", err)
	}
	q1 := r.waitPending()
	r.send(decision(q1, "allow"))
	r.waitView("import closed", func(v remote.View) bool { return len(v.Pending) == 0 })
	os.WriteFile(env, []byte("A_KEY=two\n"), 0o600)
	if _, err := r.cli.Import(ctx, wire.ImportArgs{Dotenv: env, Prefix: "imp/"}); code(err) != wire.CodePending {
		t.Fatalf("changed file must need a new approval: %v", err)
	}
	q2 := r.waitPending()
	if q2.RID == q1.RID || q2.Bind == q1.Bind || q1.Op != "import" {
		t.Fatalf("import requests %+v %+v", q1, q2)
	}
}

// (13) a detail too long to show in full is never offered to the phone.
func TestRemoteHugeDetailStaysLocal(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	helperRun(t, r.fixture, "")
	var sb strings.Builder
	sb.WriteString(basePolicy)
	for i := 0; sb.Len() < 80000; i++ {
		fmt.Fprintf(&sb, "  big/%05d/*:\n    allow_commands: [\"sql /@B%05d\"]\n    approval: user-presence\n", i, i)
	}
	r.policy(sb.String(), false)
	r.locked.Store(true)
	_, err := r.cli.PolicyApply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "không có kênh duyệt") {
		t.Fatalf("policy apply: %v", err)
	}
	r.noPendingFor(200 * time.Millisecond)
}

// (14) before the first unlock the phone channel needs state/genesis.mac; without it members.kgl is not trusted.
func TestRemoteNeedsGenesisMAC(t *testing.T) {
	var refuse atomic.Bool
	refuse.Store(true)
	r := newRemoteFix(t, rcfg{noApprover: true, mod: func(c *Config) {
		c.Approver = approve.Func(func(context.Context, string) error {
			if refuse.Load() {
				return errors.New("hủy")
			}
			return nil
		})
	}})
	r.pair() // members.kgl now has an approver, but this broker never unlocked: no genesis.mac
	if _, err := os.Stat(membersMACPath(r.home)); err == nil {
		t.Fatal("genesis.mac must not exist before an unlock")
	}
	r.restart()
	r.locked.Store(true)
	if r.b.remoteReady() {
		t.Fatal("members.kgl must not be trusted without genesis.mac")
	}
	_, err := r.cli.List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "không có kênh duyệt") {
		t.Fatalf("unlock on a locked screen without a phone channel: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if puts, _ := r.mail.counts(); puts != 0 {
		t.Fatalf("view posted without a trusted approver list (%d)", puts)
	}
	// An unlock at the machine writes genesis.mac; after a restart the phone channel is available at once.
	r.locked.Store(false)
	refuse.Store(false)
	if err := r.b.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(membersMACPath(r.home)); err != nil {
		t.Fatalf("genesis.mac not written: %v", err)
	}
	refuse.Store(true) // the restarted broker must not unlock by itself: only members.kgl + genesis.mac are available
	r.restart()
	if !r.b.remoteReady() {
		t.Fatal("approver list not restored from members.kgl + genesis.mac")
	}
	// a tampered genesis.mac is not trusted either
	r.cancel()
	waitSockGone(t, r.home)
	if err := os.WriteFile(membersMACPath(r.home), []byte("AAAA"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.restart()
	if r.b.remoteReady() {
		t.Fatal("a wrong genesis.mac must not be trusted")
	}
}

func waitSockGone(t *testing.T, home string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(SockPath(home)); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("broker socket still there")
}

// (15) the invariant: with a paired phone, a work session and a locked screen the agent runs at once,
// the phone sees no pending request and no push is requested.
func TestRemoteSessionLockedScreenNoNoise(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	req := helperRun(t, r.fixture, "")
	if err := r.cli.SessionStart(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.locked.Store(true)
	r.waitView("session visible", func(v remote.View) bool { return v.Session != nil })
	n := r.approvals.Load()
	ch, _ := r.runAsync(req)
	if o := r.await(ch); o.err != nil || o.code != 0 {
		t.Fatalf("run: %+v", o)
	}
	if r.approvals.Load() != n {
		t.Fatal("Hello must not be asked")
	}
	r.noPendingFor(300 * time.Millisecond)
	if _, pushes := r.mail.counts(); pushes != 0 {
		t.Fatalf("%d push requests for a run that needed nobody", pushes)
	}
	// and the same with a remembered grant after the session ended
	if err := r.cli.SessionEnd(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.locked.Store(false)
	r.mustRun(req)
	r.locked.Store(true)
	n = r.approvals.Load()
	r.mustRun(req)
	if r.approvals.Load() != n {
		t.Fatal("a stored grant must not need Hello on a locked screen")
	}
	r.noPendingFor(200 * time.Millisecond)
	if _, pushes := r.mail.counts(); pushes != 0 {
		t.Fatalf("%d push requests", pushes)
	}
}

// Two identical asks share one card, and the engine is empty once it is decided.
func TestRemoteSameRequestSharesOneCard(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	req := helperRun(t, r.fixture, "")
	r.locked.Store(true)
	ch1, _ := r.runAsync(req)
	p := r.waitPending()
	ch2, _ := r.runAsync(req)
	time.Sleep(200 * time.Millisecond)
	if v, _ := r.view(); len(v.Pending) != 1 || v.Pending[0].RID != p.RID {
		t.Fatalf("two identical asks must share one card: %+v", v.Pending)
	}
	r.send(decision(p, "allow"))
	for _, ch := range []<-chan runOut{ch1, ch2} {
		if o := r.await(ch); o.err != nil || o.code != 0 {
			t.Fatalf("run: %+v", o)
		}
	}
	r.engineIdle()
}

// sealLine builds a signed message line from the phone without delivering it.
func (r *rfix) sealLine(v any) (line []byte, envID string) {
	r.t.Helper()
	raw, _ := json.Marshal(v)
	line, err := remote.Seal(r.b.vaultID, r.phone, r.b.id.Dev, r.b.id.XPub, raw, time.Now())
	if err != nil {
		r.t.Fatal(err)
	}
	var env struct {
		ID string `json:"id"`
	}
	json.Unmarshal(line, &env)
	return line, env.ID
}

func (r *rfix) pushLine(relayID string, line []byte) {
	r.mail.push(relay.Msg{ID: relayID, From: r.phone.Dev, Body: line})
}

func (r *rfix) mailEmpty() {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mail.mu.Lock()
		n := len(r.mail.msgs)
		r.mail.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatal("broker did not consume the mailbox")
}

// The same signed envelope under another relay id (the relay path id is not signed), or again under
// its own id, is applied at most once; so is a reused command id.
func TestRemoteReplayUnderOtherRelayID(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	boot := r.waitView("first view", func(remote.View) bool { return true }).Boot
	cmd := func(op string) remote.Command {
		return remote.Command{Kind: remote.KindCommand, CID: remote.NewID(), Boot: boot, Op: op, Args: json.RawMessage(`{}`)}
	}
	start := cmd("session-start")
	line, envID := r.sealLine(start)
	r.pushLine(envID, line)
	r.result(start.CID)
	if !r.b.SessionOpen() {
		t.Fatal("session-start not applied")
	}
	end := cmd("session-end")
	r.result(r.command(boot, "session-end", "")) // sanity: another command still works
	_ = end
	if r.b.SessionOpen() {
		t.Fatal("session still open")
	}
	r.pushLine("AAAAAAAAAAAAAAAAAAAAAA", line) // other relay id
	r.pushLine(envID, line)                    // own id again
	r.mailEmpty()
	// a fresh envelope that reuses the command id is dropped as well
	again := start
	l2, id2 := r.sealLine(again)
	r.pushLine(id2, l2)
	r.mailEmpty()
	time.Sleep(100 * time.Millisecond)
	if r.b.SessionOpen() {
		t.Fatal("a replayed command reopened the session")
	}
}

// A remote decision must carry the request digest.
func TestRemoteEmptyDigestDropped(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	req := helperRun(t, r.fixture, "")
	r.locked.Store(true)
	ch, _ := r.runAsync(req)
	p := r.waitPending()
	d := decision(p, "allow")
	d.Digest = ""
	r.send(d)
	r.stillBlocked(ch, 300*time.Millisecond)
	r.send(decision(p, "allow"))
	if o := r.await(ch); o.err != nil || o.code != 0 {
		t.Fatalf("run: %+v", o)
	}
}

// An agent waits for the unlock; the phone sends session-start (cannot block the loop) and then the decision.
func TestRemoteLoopNotBlockedByUnlockWaiter(t *testing.T) {
	r := newRemoteFix(t, rcfg{})
	r.b.Lock()
	r.locked.Store(true)
	errc := make(chan error, 1)
	go func() { _, err := brokerclient.New(SockPath(r.home)).List(context.Background()); errc <- err }()
	p := r.waitPending()
	boot := r.b.started.UnixMilli()
	if res := r.result(r.command(boot, "session-start", "")); res.OK {
		t.Fatalf("session-start must report the pending unlock: %+v", res)
	}
	r.send(decision(p, "session"))
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("list: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the decision was never delivered")
	}
	if r.b.Locked() || !r.b.SessionOpen() {
		t.Fatalf("locked=%v session=%v", r.b.Locked(), r.b.SessionOpen())
	}
}

// Cutting the tail of members.kgl (a revoke of the phone) must not bring the phone channel back.
func TestRemoteRolledBackMembersNotTrusted(t *testing.T) {
	var refuse atomic.Bool
	r := newRemoteFix(t, rcfg{mod: func(c *Config) {
		c.Approver = approve.Func(func(context.Context, string) error {
			if refuse.Load() {
				return errors.New("hủy")
			}
			return nil
		})
	}})
	r.withStore(func(st *store.Store) {
		if _, err := st.RevokeDevice(r.keys.OwnerPriv, r.phone.Dev, "test"); err != nil {
			t.Fatal(err)
		}
	})
	if err := r.b.Unlock(context.Background()); err != nil { // members.mac now covers the revoke
		t.Fatal(err)
	}
	r.cancel()
	waitSockGone(t, r.home)
	path := filepath.Join(r.home, "members.kgl")
	data, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if len(lines) < 3 {
		t.Fatalf("members.kgl has %d lines", len(lines))
	}
	// drop revoke + epoch: the phone looks active again
	if err := os.WriteFile(path, append(bytes.Join(lines[:len(lines)-2], []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	refuse.Store(true)
	r.restart()
	if r.b.remoteReady() {
		t.Fatal("a rolled-back members.kgl must not restore the revoked approver")
	}
}
