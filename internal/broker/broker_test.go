package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"keygate/internal/allowlist"
	"keygate/internal/api"
	"keygate/internal/approve"
	"keygate/internal/audit"
	"keygate/internal/broker/wire"
	"keygate/internal/brokerclient"
	"keygate/internal/devkey"
	"keygate/internal/kcrypto"
	"keygate/internal/policy"
	"keygate/internal/record"
	"keygate/internal/recovery"
	"keygate/internal/store"
	"keygate/internal/syncer"
	"keygate/internal/transport"
	"keygate/internal/transport/dir"
)

// stubPrompt is the broker TTY: queued answers, captured output.
type stubPrompt struct {
	mu      sync.Mutex
	secrets []string
	lines   []string
	out     bytes.Buffer
}

func (p *stubPrompt) pop(q *[]string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(*q) == 0 {
		return "", errors.New("stub: no queued answer")
	}
	v := (*q)[0]
	*q = (*q)[1:]
	return v, nil
}
func (p *stubPrompt) ReadLine(ctx context.Context, _ string) (string, error) { return p.pop(&p.lines) }
func (p *stubPrompt) ReadSecret(ctx context.Context, _ string) (string, error) {
	return p.pop(&p.secrets)
}
func (p *stubPrompt) ShowSecret(ctx context.Context, name, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(&p.out, "\n[KeyGate reveal] %s = %s\n", name, value)
	return nil
}
func (p *stubPrompt) Review(ctx context.Context, title, text string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(&p.out, "\n[Review] %s\n%s\n", title, text)
	return nil
}
func (p *stubPrompt) Out() io.Writer { return &lockedWriter{p} }
func (p *stubPrompt) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

type lockedWriter struct{ p *stubPrompt }

func (w *lockedWriter) Write(b []byte) (int, error) {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	return w.p.out.Write(b)
}

type fixture struct {
	t         *testing.T
	home      string
	st        *store.Store
	keys      *recovery.Keys
	paper     string // human form of the paper key
	approvals atomic.Int32
	prompt1   atomic.Value // last prompt the local approver showed
	refuse    atomic.Bool
	locked    atomic.Bool
	cfg       Config
	prompt    *stubPrompt
	b         *Broker
	cli       *brokerclient.Client
	cancel    context.CancelFunc
	version   uint64
}

func lowArgon() kcrypto.Argon2Params { return kcrypto.Argon2Params{T: 1, M: 64, P: 1} }

// fakeSQL puts a fake `sql` program first on PATH so allow_commands can be resolved.
func fakeSQL(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	name := "sql"
	if runtime.GOOS == "windows" {
		name = "sql.exe"
	}
	if err := os.WriteFile(filepath.Join(d, name), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", d+string(os.PathListSeparator)+os.Getenv("PATH"))
	return d
}

func newFixture(t *testing.T, idle, poll time.Duration) *fixture {
	return newFixtureWith(t, idle, poll, nil)
}

// newFixtureWith is newFixture with a Config mutator (applied last).
func newFixtureWith(t *testing.T, idle, poll time.Duration, mod func(*Config)) *fixture {
	t.Helper()
	t.Setenv(devkey.EnvBackend, "plain")
	fakeSQL(t)
	f := &fixture{t: t, home: t.TempDir(), prompt: &stubPrompt{}}
	vault := kcrypto.NewVaultID()
	setup, err := recovery.NewSetup(vault, "pw-pw-pw-pw-pw-pw", lowArgon())
	if err != nil {
		t.Fatal(err)
	}
	f.keys, f.paper = setup.Keys, setup.PaperKey
	id := store.NewIdentity("dev-a")
	if err := store.SaveIdentity(f.home, id, devkey.NewPlain(f.home)); err != nil {
		t.Fatal(err)
	}
	if f.st, err = store.Init(f.home, vault, id, setup.Keys, setup.Salt, setup.Params, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.st.Close() // the broker takes KG_HOME/lock; the fixture reopens only when it must write
	cfg := Config{
		Home: f.home, IdleLock: idle, ScreenPoll: poll, Prompt: f.prompt, RevealCooldown: 300 * time.Millisecond,
		LockOnScreenLock: true,
		Approver: approve.Func(func(_ context.Context, prompt string) error {
			f.approvals.Add(1)
			f.prompt1.Store(prompt)
			if f.refuse.Load() {
				return errors.New("người dùng từ chối")
			}
			return nil
		}),
		ScreenLocked: func() bool { return f.locked.Load() },
		Keys:         func() (devkey.Store, error) { return devkey.NewPlain(f.home), nil },
	}
	if mod != nil {
		mod(&cfg)
	}
	f.cfg = cfg
	f.b, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.start()
	f.b.endSession("test") // existing tests exercise the no-session behaviour
	return f
}

func (f *fixture) start() {
	t := f.t
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	ready := make(chan struct{})
	f.b.OnListen(func() { close(ready) })
	done := make(chan error, 1)
	go func() { done <- f.b.Serve(ctx) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("serve: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("serve timeout")
	}
	t.Cleanup(func() { cancel(); <-done })
	f.cli = brokerclient.New(SockPath(f.home))
}

// withStore lets the test write through its own store while the broker is locked.
func (f *fixture) withStore(fn func(st *store.Store)) {
	f.t.Helper()
	f.b.Lock()
	id, err := store.LoadIdentity(f.home, devkey.NewPlain(f.home))
	if err != nil {
		f.t.Fatal(err)
	}
	st, err := store.Open(f.home, id)
	if err != nil {
		f.t.Fatal(err)
	}
	defer st.Close()
	f.st = st
	fn(st)
}

func (f *fixture) put(item, name, env string) {
	f.t.Helper()
	f.withStore(func(st *store.Store) {
		if _, err := st.Put(item, record.Plain{Name: name, Value: "value-" + name, Env: env, Kind: "env"}); err != nil {
			f.t.Fatal(err)
		}
	})
}

// policy writes policy.yaml and (when pin) a pin with the next version, MAC'd with the device key.
func (f *fixture) policy(text string, pin bool) {
	f.t.Helper()
	data := []byte(text)
	if err := os.WriteFile(filepath.Join(f.home, "policy.yaml"), data, 0o600); err != nil {
		f.t.Fatal(err)
	}
	if pin {
		f.version++
		id, _ := store.LoadIdentity(f.home, devkey.NewPlain(f.home))
		mac := kcrypto.HKDF(id.EdPriv.Seed(), []byte(kcrypto.LabelLocalMac), 32)
		if err := policy.WritePin(filepath.Join(f.home, "state", "policy.pin"), data, mac, f.version); err != nil {
			f.t.Fatal(err)
		}
	}
}

func code(err error) string {
	var e *brokerclient.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

const basePolicy = `grants:
  ebs/test/*:
    allow_commands: ["sql /@HTTEST"]
    approval: user-presence
    ttl: 10m
  ht/prod/exact:
    allow_commands: ["sql /@PROD"]
    approval: user-presence
  ht/prod/*:
    allow_commands: ["sql /@PROD"]
    approval: user-presence
  ebs/prd/*:
    allow_commands: ["sql /@PROD"]
    approval: user-presence
`

var sqlArgv = []string{"sql", "/@HTTEST"}

func TestPinAndGrantLifecycle(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "ebs/test/a", "test")
	f.policy(basePolicy, false)
	ctx := context.Background()

	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); code(err) != wire.CodePolicy {
		t.Fatalf("missing pin: %v", err)
	}
	f.policy(basePolicy, true)
	before := f.approvals.Load()
	g, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t")
	if err != nil || g.Pattern != "sql /@HTTEST" || g.Approval != "user-presence" {
		t.Fatalf("grant: %+v %v", g, err)
	}
	if f.approvals.Load() != before+1 {
		t.Fatal("approval not asked")
	}
	// Cached for the TTL, keyed by (secret, entry, resolved program).
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", append(sqlArgv, "@x.sql"), "t"); err != nil || f.approvals.Load() != before+1 {
		t.Fatalf("cached grant: %v approvals=%d", err, f.approvals.Load())
	}
	st, _ := f.cli.Status(ctx)
	if len(st.Grants) != 1 || !st.PolicyOK || !st.Unlocked {
		t.Fatalf("status %+v", st)
	}
	// Anything but the bare name / resolved path, shells, other args: refused (C1).
	for _, argv := range [][]string{
		{"curl", "x"}, {"bash", "-c", "x"}, {filepath.Join(t.TempDir(), "sql"), "/@HTTEST"}, {"./sql", "/@HTTEST"}, {"sql", "/@OTHER"}, {"sql", "/@HTTEST", "-R", "0"},
	} {
		if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", argv, "t"); code(err) != wire.CodeBlocked {
			t.Errorf("%v must be blocked: %v", argv, err)
		}
	}
	// Tampered policy.yaml (pin mismatch) => deny.
	f.policy(basePolicy+"  extra:\n    approval: none\n", false)
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); code(err) != wire.CodePolicy {
		t.Fatalf("tampered policy: %v", err)
	}
	if st, _ := f.cli.Status(ctx); st.PolicyOK {
		t.Fatal("status must report policy not ok")
	}
}

func TestPolicyRollbackRefused(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "ebs/test/a", "test")
	f.policy(basePolicy, true) // v1
	ctx := context.Background()
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(filepath.Join(f.home, "state", "policy.pin"))
	f.policy(basePolicy+"  more:\n    approval: deny\n", true) // v2
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); err != nil {
		t.Fatal(err)
	}
	// Restoring the old (valid, MAC'd) pin+policy pair must be refused: version went backwards.
	os.WriteFile(filepath.Join(f.home, "policy.yaml"), []byte(basePolicy), 0o600)
	os.WriteFile(filepath.Join(f.home, "state", "policy.pin"), old, 0o600)
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); code(err) != wire.CodePolicy {
		t.Fatalf("rollback must be refused: %v", err)
	}
}

func TestProdDefaultDeny(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "ht/prod/other", "prod")
	f.put("", "ht/prod/exact", "prod")
	f.put("", "ebs/test/x", "prod") // env=prod by tag, name is not prod-looking
	f.put("", "ebs/prd/y", "dev")   // prd segment, env says dev
	f.policy(basePolicy, true)
	ctx := context.Background()
	prod := []string{"sql", "/@PROD"}
	for _, n := range []string{"ht/prod/other", "ebs/test/x", "ebs/prd/y"} {
		if _, err := f.cli.RequestGrant(ctx, n, prod, "t"); code(err) != wire.CodeDenied {
			t.Errorf("%s: glob grant must not open PROD: %v", n, err)
		}
	}
	if _, err := f.cli.RequestGrant(ctx, "ht/prod/exact", prod, "t"); err != nil {
		t.Fatalf("exact user-presence grant: %v", err)
	}
}

func TestAutoLockAndRelock(t *testing.T) {
	f := newFixture(t, 300*time.Millisecond, 20*time.Millisecond)
	f.put("", "ebs/test/a", "test")
	f.policy(basePolicy, true)
	ctx := context.Background()
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); err != nil {
		t.Fatal(err)
	}
	// L3: list/status by an agent must not keep the vault unlocked.
	deadline := time.Now().Add(5 * time.Second)
	for !f.b.Locked() && time.Now().Before(deadline) {
		f.cli.Status(ctx)
		time.Sleep(30 * time.Millisecond)
	}
	if !f.b.Locked() {
		t.Fatal("did not auto-lock while only status calls arrived")
	}
	st, _ := f.cli.Status(ctx)
	if st.Unlocked || len(st.Grants) != 1 {
		t.Fatalf("locked status keeps the durable grant: %+v", st)
	}
	before := f.approvals.Load()
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); err != nil {
		t.Fatal(err)
	}
	if f.approvals.Load() != before+1 {
		t.Fatalf("expected the unlock approval only (grant is remembered), got %d", f.approvals.Load()-before)
	}
}

func TestScreenLock(t *testing.T) {
	f := newFixture(t, time.Hour, 20*time.Millisecond)
	f.locked.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for !f.b.Locked() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !f.b.Locked() {
		t.Fatal("screen lock must clear the vault key")
	}
}

func TestSetImportRevealNeverOverSocket(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	ctx := context.Background()
	// A value in the request is refused outright (H4).
	if err := f.cli.Set(ctx, wire.SetArgs{Request: api.SetRequest{Name: "a/b", Value: "leak", Kind: "env"}}); code(err) != wire.CodeBadRequest {
		t.Fatalf("value over socket must be refused: %v", err)
	}
	// New name: the broker asks on ITS terminal; no extra approval needed.
	f.prompt.secrets = []string{"v-12345"}
	base := f.approvals.Load()
	if err := f.cli.Set(ctx, wire.SetArgs{Request: api.SetRequest{Name: "a/b", Kind: "env", Env: " Test "}}); err != nil {
		t.Fatal(err)
	}
	if f.approvals.Load() != base {
		t.Fatal("new secret must not need an extra approval")
	}
	// Overwrite needs user-presence (M2); a refusal keeps the old value.
	f.prompt.secrets = []string{"v-OVERWRITTEN"}
	f.refuse.Store(true)
	if err := f.cli.Set(ctx, wire.SetArgs{Request: api.SetRequest{Name: "a/b", Kind: "env"}}); code(err) != wire.CodeDenied {
		t.Fatalf("overwrite without approval: %v", err)
	}
	f.refuse.Store(false)
	if err := f.cli.Set(ctx, wire.SetArgs{Request: api.SetRequest{Name: "w", Kind: "oracle-wallet"}}); code(err) != wire.CodeBadRequest {
		t.Fatalf("wallet w/o user: %v", err)
	}
	if err := f.cli.Set(ctx, wire.SetArgs{Request: api.SetRequest{Name: "x", Kind: "env", EnvName: "JAVA_TOOL_OPTIONS"}}); code(err) != wire.CodeBadRequest {
		t.Fatalf("loader env name: %v", err)
	}
	l, err := f.cli.List(ctx)
	if err != nil || len(l) != 1 || l[0].Name != "a/b" || l[0].Env != "test" {
		t.Fatalf("list %+v %v", l, err)
	}
	// reveal prints on the broker terminal only.
	if err := f.cli.Reveal(ctx, "a/b"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.prompt.String(), "v-12345") {
		t.Fatal("value must be shown on the broker terminal")
	}
	// refusal => cooldown (M8)
	f.refuse.Store(true)
	if err := f.cli.Reveal(ctx, "a/b"); code(err) != wire.CodeDenied {
		t.Fatalf("refused reveal: %v", err)
	}
	f.refuse.Store(false)
	n := f.approvals.Load()
	if err := f.cli.Reveal(ctx, "a/b"); code(err) != wire.CodeDenied || f.approvals.Load() != n {
		t.Fatalf("cooldown must block without prompting: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if err := f.cli.Reveal(ctx, "a/b"); err != nil {
		t.Fatalf("after cooldown: %v", err)
	}
	if err := f.cli.Lock(ctx); err != nil || !f.b.Locked() {
		t.Fatal("lock")
	}
}

func TestImportReadsFileItself(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	ctx := context.Background()
	envf := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(envf, []byte("OPENAI_API_KEY=sk-test-123456\nPATH=/evil\n"), 0o600)
	f.refuse.Store(true)
	if _, err := f.cli.Import(ctx, wire.ImportArgs{Dotenv: envf, Prefix: "llm/", Rewrite: true}); code(err) != wire.CodeDenied {
		t.Fatalf("import needs approval: %v", err)
	}
	if b, _ := os.ReadFile(envf); !strings.Contains(string(b), "sk-test-123456") {
		t.Fatal("file must be untouched after refusal")
	}
	f.refuse.Store(false)
	r, err := f.cli.Import(ctx, wire.ImportArgs{Dotenv: envf, Prefix: "llm/", Rewrite: true})
	if err != nil || r.Count != 2 {
		t.Fatalf("import: %+v %v", r, err)
	}
	b, _ := os.ReadFile(envf)
	if strings.Contains(string(b), "sk-test-123456") || !strings.Contains(string(b), "${secret:llm/openai-api-key}") {
		t.Fatalf("file not rewritten: %s", b)
	}
}

func TestPolicyApplyDiffFlushAndVersion(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "ebs/test/a", "test")
	ctx := context.Background()
	f.policy(basePolicy, false)
	if _, err := f.cli.PolicyApply(ctx); err != nil { // v1
		t.Fatal(err)
	}
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.cli.Status(ctx); len(st.Grants) != 1 {
		t.Fatal("grant expected")
	}
	// Agent-style widening: approval none + wildcard. The broker TTY must show it, and apply flushes grants.
	sqlp, _ := exec.LookPath("sql")
	sqlh, _ := allowlist.FileHash(sqlp)
	f.policy(basePolicy+"  \"*\":\n    allow_commands: [\"\\\""+filepath.ToSlash(sqlp)+"\\\" "+sqlh+" **\"]\n    approval: none\n", false)
	if _, err := f.cli.PolicyApply(ctx); err != nil { // v2
		t.Fatal(err)
	}
	out := f.prompt.String()
	for _, want := range []string{"+ THÊM quyền dùng secret *", "approval none", "glob", "Ai yêu cầu: "} {
		if !strings.Contains(out, want) {
			t.Errorf("TTY output lacks %q:\n%s", want, out)
		}
	}
	if st, _ := f.cli.Status(ctx); len(st.Grants) != 1 || !st.PolicyOK {
		t.Fatalf("durable grant of an unchanged allow_commands entry must stay: %+v", st)
	}
	pin, _ := os.ReadFile(filepath.Join(f.home, "state", "policy.pin"))
	if !strings.Contains(string(pin), `"version":2`) {
		t.Fatalf("pin version: %s", pin)
	}
}

func TestKindRules(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.withStore(func(st *store.Store) {
		for _, p := range []record.Plain{
			{Name: "ebs/test/w", Value: "pw-value-1", Env: "test", Kind: "oracle-wallet", User: "u", TNS: "al"},
			{Name: "ebs/test/e", Value: "env-value-1", Env: "test", Kind: "env"},
			{Name: "ebs/test/t", Value: "tpl-value-1", Env: "test", Kind: "template"},
		} {
			if _, err := st.Put("", p); err != nil {
				t.Fatal(err)
			}
		}
	})
	f.policy(`grants:
  ebs/test/w:
    allow_commands: ["sql /@HTTEST"]
    approval: user-presence
    allow_as: [env]
  ebs/test/e:
    allow_commands: ["sql /@HTTEST"]
    approval: user-presence
  ebs/test/t:
    kind: template
    allow_commands: ["sql /@HTTEST"]
    approval: user-presence
`, true)
	ctx := context.Background()
	run := func(name, as string, resolve bool) error {
		req := api.RunRequest{Secrets: []string{name}, Argv: sqlArgv, As: as, Agent: "t"}
		if resolve {
			tp := filepath.Join(t.TempDir(), "t.txt")
			os.WriteFile(tp, []byte("x=${secret:"+name+"}"), 0o600)
			req.Resolve = tp
			req.Secrets = nil
		}
		_, err := f.cli.Run(ctx, req, io.Discard, io.Discard)
		return err
	}
	if err := run("ebs/test/w", "env", false); code(err) != wire.CodeBlocked {
		t.Fatalf("--as must not change a wallet even if allow_as lists it: %v", err)
	}
	if err := run("ebs/test/e", "file", false); code(err) != wire.CodeBlocked {
		t.Fatalf("--as without allow_as: %v", err)
	}
	if err := run("ebs/test/e", "", true); code(err) != wire.CodeBlocked {
		t.Fatalf("resolve of a non-template secret: %v", err)
	}
}

// TestRunRedactedAndAudited runs a real child (the test binary) through the broker.
func TestRunRedactedAndAudited(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	const value = "s3cr3t-Value-ABC123xyz"
	f.withStore(func(st *store.Store) {
		if _, err := st.Put("", record.Plain{Name: "ebs/test/tok", Value: value, Env: "test", Kind: "env", EnvName: "MY_TOKEN"}); err != nil {
			t.Fatal(err)
		}
	})
	exe, _ := filepath.Abs(os.Args[0])
	exeHash, herr := allowlist.FileHash(exe)
	if herr != nil {
		t.Fatal(herr)
	}
	f.policy(`grants:
  ebs/test/tok:
    allow_commands: ["\"`+filepath.ToSlash(exe)+`\" `+exeHash+` -test.run=TestBrokerHelper"]
    approval: none
    max_runtime: 1m
`, true)
	t.Setenv("KG_BROKER_HELPER", "1")
	t.Setenv("KG_HELPER_VAR", "MY_TOKEN")
	ctx := context.Background()
	var out bytes.Buffer
	code, err := f.cli.Run(ctx, api.RunRequest{Secrets: []string{"ebs/test/tok"}, Argv: []string{exe, "-test.run=TestBrokerHelper"}, Agent: "t"}, &out, &out)
	if err != nil || code != 0 {
		t.Fatalf("run: %d %v\n%s", code, err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "plain=[kg:ebs/test/tok]") || !strings.Contains(got, "b64=[kg:ebs/test/tok]") || !strings.Contains(got, "err=[kg:ebs/test/tok]") {
		t.Fatalf("not redacted:\n%s", got)
	}
	if strings.Contains(got, value) || strings.Contains(got, base64.StdEncoding.EncodeToString([]byte(value))) {
		t.Fatal("secret leaked")
	}
	// run-start precedes run, peer recorded, anchor verifies.
	led := audit.Open(filepath.Join(f.home, "audit", "ledger.jsonl"), filepath.Join(f.home, "state", "audit.head"), f.st.LocalMacKey())
	es, err := led.ShowVerified(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var evs []string
	for _, e := range es {
		if e.Event == audit.EvSession {
			continue
		}
		evs = append(evs, e.Event)
		if e.Peer == "" {
			t.Errorf("entry %s lacks peer", e.Event)
		}
	}
	if strings.Join(evs, ",") != "grant,run-start,run" && strings.Join(evs, ",") != "run-start,run" {
		t.Fatalf("events %v", evs)
	}
	// If the audit cannot be appended the command must not run (M3).
	os.Remove(filepath.Join(f.home, "state", "audit.head"))
	out.Reset()
	_, err = f.cli.Run(ctx, api.RunRequest{Secrets: []string{"ebs/test/tok"}, Argv: []string{exe, "-test.run=TestBrokerHelper"}, Agent: "t"}, &out, &out)
	if err == nil || out.Len() != 0 {
		t.Fatalf("run must be refused when audit fails: %v %q", err, out.String())
	}
	// run dir is swept/clean
	ents, _ := os.ReadDir(RunDir(f.home))
	if len(ents) != 0 {
		t.Fatalf("temp material left: %d", len(ents))
	}
}

func TestBrokerHelper(t *testing.T) {
	if os.Getenv("KG_BROKER_HELPER") != "1" {
		return
	}
	v := os.Getenv(os.Getenv("KG_HELPER_VAR"))
	os.Stdout.WriteString("plain=" + v + "\n")
	os.Stdout.WriteString("b64=" + base64.StdEncoding.EncodeToString([]byte(v)) + "\n")
	os.Stderr.WriteString("err=" + v + "\n")
	os.Exit(0)
}

func TestConflictRefused(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	ctx := context.Background()
	shared := t.TempDir()
	f.b.Lock()
	id1, err := store.LoadIdentity(f.home, devkey.NewPlain(f.home))
	if err != nil {
		t.Fatal(err)
	}
	st1, err := store.Open(f.home, id1)
	if err != nil {
		t.Fatal(err)
	}
	t1, _ := dir.New(shared, st1.ID.Dev)
	s1 := &syncer.Syncer{Store: st1, T: t1}
	id2 := store.NewIdentity("dev-b")
	if err := st1.AddDevice(f.keys.OwnerPriv, id2.Public()); err != nil {
		t.Fatal(err)
	}
	r, err := st1.Put("", record.Plain{Name: "ebs/test/c", Value: "v1", Env: "test", Kind: "env"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	t2, _ := dir.New(shared, id2.Dev)
	snap, err := t2.Pull(ctx, transport.Since{})
	if err != nil {
		t.Fatal(err)
	}
	st2, err := store.Join(t.TempDir(), id2, snap, store.GenesisPinOf(st1.Vault(), st1.Members().GenesisHash))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	s2 := &syncer.Syncer{Store: st2, T: t2}
	if _, err := s2.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// Concurrent edits of the same item from the same parent => two heads.
	if _, err := st2.Put(r.Item, record.Plain{Name: "ebs/test/c", Value: "from-b", Env: "test", Kind: "env"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st1.Put(r.Item, record.Plain{Name: "ebs/test/c", Value: "from-a", Env: "test", Kind: "env"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*syncer.Syncer{s2, s1, s2} {
		if _, err := s.Sync(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(st1.Conflicts()) != 1 {
		t.Fatal("expected a conflict")
	}
	st1.Close()
	f.f_policy(basePolicy)
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/c", sqlArgv, "t"); code(err) != wire.CodeConflict {
		t.Fatalf("conflicted secret must be refused: %v", err)
	}
	cs, err := f.cli.Conflicts(ctx)
	if err != nil || len(cs) != 1 || len(cs[0].Heads) != 2 {
		t.Fatalf("conflicts %+v %v", cs, err)
	}
	// resolving needs a human (M2)
	f.refuse.Store(true)
	if err := f.cli.ResolveConflict(ctx, wire.ResolveConflictArgs{Name: "ebs/test/c", Keep: id2.Dev}); code(err) != wire.CodeDenied {
		t.Fatalf("resolve without approval: %v", err)
	}
	f.refuse.Store(false)
	if err := f.cli.ResolveConflict(ctx, wire.ResolveConflictArgs{Name: "ebs/test/c", Keep: id2.Dev}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/c", sqlArgv, "t"); err != nil {
		t.Fatalf("after resolve: %v", err)
	}
}

// f_policy pins the policy while the broker is locked (no store handle needed).
func (f *fixture) f_policy(text string) { f.policy(text, true) }

func TestDeleteBatchAllOrNothing(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "d/a", "dev")
	f.put("", "d/b", "dev")
	ctx := context.Background()
	n := f.approvals.Load()
	if _, err := f.cli.Delete(ctx, []string{"d/a", "d/missing"}); code(err) != wire.CodeNotFound {
		t.Fatalf("unknown name: %v", err)
	}
	if l, _ := f.cli.List(ctx); len(l) != 2 {
		t.Fatalf("nothing may be deleted: %+v", l)
	}
	f.refuse.Store(true)
	if _, err := f.cli.Delete(ctx, []string{"d/a"}); code(err) != wire.CodeDenied {
		t.Fatalf("needs approval: %v", err)
	}
	f.refuse.Store(false)
	before := f.approvals.Load()
	r, err := f.cli.Delete(ctx, []string{"d/a", "d/b"})
	if err != nil || len(r.Names) != 2 || f.approvals.Load() != before+1 {
		t.Fatalf("%+v %v approvals=%d", r, err, f.approvals.Load()-before)
	}
	if l, _ := f.cli.List(ctx); len(l) != 0 {
		t.Fatalf("left: %+v", l)
	}
	if fp, err := f.cli.Fingerprint(ctx); err != nil || fp == "" {
		t.Fatalf("fingerprint %q %v", fp, err)
	}
	_ = n
}

// Delete only hides a secret (append-only logs), so its approval must say so, even for a long batch.
func TestDeleteApprovalWarnsHistoryKept(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	var names []string
	for i := 0; i < 8; i++ {
		n := fmt.Sprintf("team/%s/%d", strings.Repeat("long-name-", 4), i)
		f.put("", n, "dev")
		names = append(names, n)
	}
	for _, batch := range [][]string{names[:1], names[1:]} {
		if _, err := f.cli.Delete(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
		p, _ := f.prompt1.Load().(string)
		if !strings.Contains(p, deleteHistoryWarning) || !strings.Contains(p, batch[0]) {
			t.Fatalf("delete prompt lacks the history warning or the name: %q", p)
		}
	}
}

func TestBatchApprovalAndCompare(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "ebs/test/a", "test")
	f.put("", "ebs/test/b", "test")
	f.policy(basePolicy, true)
	ctx := context.Background()
	// Two ungranted secrets in one run: ONE approval (plus none for unlock: already unlocked).
	if _, err := f.cli.List(ctx); err != nil {
		t.Fatal(err)
	}
	before := f.approvals.Load()
	_, err := f.cli.Run(ctx, api.RunRequest{Secrets: []string{"ebs/test/a", "ebs/test/b"}, Argv: sqlArgv, Agent: "t"}, io.Discard, io.Discard)
	_ = err                                          // the fake sql is not runnable; only the approval count matters
	if got := f.approvals.Load() - before; got > 2 { // unlock may add one after withStore locked it
		t.Fatalf("expected a single batch approval, got %d", got)
	}
	st, _ := f.cli.Status(ctx)
	if len(st.Grants) != 2 {
		t.Fatalf("both grants cached: %+v", st.Grants)
	}
	// One failing secret blocks the whole batch before any prompt.
	n := f.approvals.Load()
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", []string{"curl"}, "t"); err == nil || f.approvals.Load() != n {
		t.Fatalf("blocked command must not prompt: %v", err)
	}

	envf := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(envf, []byte("A_KEY=value-a\nB_KEY=other\nNEW_KEY=n\nbad line here\nC: x\n"), 0o600)
	f.prompt.secrets = []string{"value-a"}
	f.prompt.secrets = nil
	f.withStore(func(st *store.Store) {
		st.Put("", record.Plain{Name: "p/a-key", Value: "value-a", Env: "dev", Kind: "env"})
		st.Put("", record.Plain{Name: "p/b-key", Value: "DIFFERENT", Env: "dev", Kind: "env"})
		st.Put("", record.Plain{Name: "p/gone", Value: "g", Env: "dev", Kind: "env"})
	})
	r, err := f.cli.Compare(ctx, wire.ImportArgs{Dotenv: envf, Prefix: "p/"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, it := range r.Items {
		got[it.Name] = it.Status
	}
	if got["p/a-key"] != "same" || got["p/b-key"] != "diff" || got["p/new-key"] != "missing" {
		t.Fatalf("%+v", r)
	}
	if len(r.Extra) != 1 || r.Extra[0] != "p/gone" || len(r.Unparsed) != 2 || r.Unparsed[0] != 4 || r.Unparsed[1] != 5 {
		t.Fatalf("%+v", r)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "value-a") || strings.Contains(string(b), "DIFFERENT") {
		t.Fatal("values leaked")
	}
	f.refuse.Store(true)
	if _, err := f.cli.Compare(ctx, wire.ImportArgs{Dotenv: envf, Prefix: "p/"}); code(err) != wire.CodeDenied {
		t.Fatalf("compare needs approval: %v", err)
	}
}

func TestImportThenDeleteByListedName(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	ctx := context.Background()
	envf := filepath.Join(t.TempDir(), ".env")
	var sb strings.Builder
	for i := 0; i < 170; i++ {
		sb.WriteString("KEY_" + strconv.Itoa(i) + "=v" + strconv.Itoa(i) + "xxxx\r\n")
	}
	sb.WriteString("ALLOWED_HOSTS=a.example.com,b.example.com\r\n")
	os.WriteFile(envf, []byte(sb.String()), 0o600)
	if _, err := f.cli.Import(ctx, wire.ImportArgs{Dotenv: envf, Prefix: "app/"}); err != nil {
		t.Fatal(err)
	}
	l, _ := f.cli.List(ctx)
	var names []string
	for _, s := range l {
		names = append(names, s.Name)
	}
	if len(names) != 171 {
		t.Fatalf("listed %d", len(names))
	}
	// Names with a stray CR/space (as pasted from CRLF files) must still resolve; the error must show it.
	if _, err := f.cli.Delete(ctx, []string{"app/nope\r"}); err == nil || !strings.Contains(err.Error(), `\r`) {
		t.Fatalf("error must reveal hidden chars: %v", err)
	}
	crlf := make([]string, len(names))
	for i, n := range names {
		crlf[i] = n + "\r"
	}
	r, err := f.cli.Delete(ctx, crlf)
	if err != nil || len(r.Names) != 171 {
		t.Fatalf("delete: %v %d", err, len(r.Names))
	}
}

func TestWorkSession(t *testing.T) {
	f := newFixture(t, 200*time.Millisecond, 20*time.Millisecond)
	f.put("", "ebs/test/a", "test")
	f.put("", "ht/prod/exact", "prod")
	f.put("", "ht/prod/other", "prod")
	f.put("", "dd", "test")
	f.policy(basePolicy+"  dd:\n    allow_commands: [\"sql /@HTTEST\"]\n    approval: deny\n", true)
	ctx := context.Background()
	prod := []string{"sql", "/@PROD"}

	// Without a session: prompts. With: none, including the PROD exact grant.
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); err != nil {
		t.Fatal(err)
	}
	f.b.mu.Lock()
	f.b.grants = map[grantKey]grantEntry{} // forget the durable one too: this test is about the session
	f.b.mu.Unlock()
	n := f.approvals.Load()
	if err := f.cli.SessionStart(ctx); err != nil {
		t.Fatal(err)
	}
	if f.approvals.Load() != n+1 {
		t.Fatal("session start must prompt once")
	}
	sf, _ := f.cli.StatusFull(ctx)
	if !sf.Session || sf.SessionStart == nil {
		t.Fatalf("status %+v", sf)
	}
	n = f.approvals.Load()
	g, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t")
	if err != nil || g.Approval != "session" {
		t.Fatalf("%+v %v", g, err)
	}
	if _, err := f.cli.RequestGrant(ctx, "ht/prod/exact", prod, "t"); err != nil {
		t.Fatalf("PROD exact grant in session: %v", err)
	}
	if f.approvals.Load() != n {
		t.Fatal("no prompt expected inside a session")
	}
	// deny and PROD default-deny still deny
	if _, err := f.cli.RequestGrant(ctx, "dd", sqlArgv, "t"); code(err) != wire.CodeDenied {
		t.Fatalf("approval: deny: %v", err)
	}
	if _, err := f.cli.RequestGrant(ctx, "ht/prod/other", prod, "t"); code(err) != wire.CodeDenied {
		t.Fatalf("PROD default-deny: %v", err)
	}
	// policy apply still prompts
	n = f.approvals.Load()
	if _, err := f.cli.PolicyApply(ctx); err != nil {
		t.Fatal(err)
	}
	if f.approvals.Load() != n+1 {
		t.Fatal("policy apply must prompt in a session")
	}
	// idle and screen lock are disabled during the session
	f.locked.Store(true)
	time.Sleep(700 * time.Millisecond)
	if f.b.Locked() {
		t.Fatal("auto-lock must be disabled in a session")
	}
	f.locked.Store(false)
	// ending restores prompts and auto-lock; grants are dropped
	if err := f.cli.SessionEnd(ctx); err != nil {
		t.Fatal(err)
	}
	n = f.approvals.Load()
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); err != nil || f.approvals.Load() < n+1 {
		t.Fatalf("prompt expected after session end: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !f.b.Locked() && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}
	if !f.b.Locked() {
		t.Fatal("idle auto-lock must work again after session end")
	}
	// audit records approval=session with an id
	led := audit.Open(filepath.Join(f.home, "audit", "ledger.jsonl"), filepath.Join(f.home, "state", "audit.head"), f.st.LocalMacKey())
	es, err := led.ShowVerified(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range es {
		if e.Event == audit.EvGrant && e.Approval == "session" && e.Session != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("grant audit lacks approval=session + session id")
	}
}

func TestHashPinInBroker(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.put("", "ebs/test/a", "test")
	script := filepath.Join(t.TempDir(), "job.py")
	os.WriteFile(script, []byte("print(1)"), 0o644)
	h, _ := allowlist.FileHash(script)
	py := "python"
	if runtime.GOOS == "windows" {
		py = "python.exe"
	}
	os.WriteFile(filepath.Join(filepath.Dir(mustLook(t, "sql")), py), []byte("x"), 0o755)
	sp := filepath.ToSlash(script)
	f.policy("grants:\n  ebs/test/a:\n    allow_commands: [\"python path:"+sp+" "+h+"\"]\n    approval: none\n", true)
	ctx := context.Background()
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", []string{"python", script}, "t"); err != nil {
		t.Fatalf("matching hash: %v", err)
	}
	os.WriteFile(script, []byte("print(2)"), 0o644)
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", []string{"python", script}, "t"); code(err) != wire.CodeBlocked {
		t.Fatalf("changed script must be denied: %v", err)
	}
}

func mustLook(t *testing.T, name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSameAndCopy(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.withStore(func(st *store.Store) {
		for _, p := range []record.Plain{
			{Name: "s/a", Value: "val-1", Env: "dev", Kind: "env", EnvName: "A_TOK", Desc: "d", Tags: []string{"t"}},
			{Name: "s/b", Value: "val-1", Env: "dev", Kind: "env"},
			{Name: "s/c", Value: "other", Env: "dev", Kind: "env"},
			{Name: "s/w", Value: "pw-9", Env: "test", Kind: "oracle-wallet", User: "u", TNS: "al"},
		} {
			if _, err := st.Put("", p); err != nil {
				t.Fatal(err)
			}
		}
	})
	ctx := context.Background()
	if err := f.cli.SessionStart(ctx); err != nil { // always-Hello must hold even in a session
		t.Fatal(err)
	}
	n := f.approvals.Load()
	r, err := f.cli.Same(ctx, []string{"s/a", "s/b", "s/c"})
	if err != nil || len(r.Items) != 2 || r.Items[0].Status != "same" || r.Items[1].Status != "diff" {
		t.Fatalf("%+v %v", r, err)
	}
	if f.approvals.Load() != n+1 {
		t.Fatal("same must prompt even in a session")
	}
	if _, err := f.cli.Same(ctx, []string{"s/a", "s/nope"}); code(err) != wire.CodeNotFound {
		t.Fatalf("%v", err)
	}
	// copy: batch, one prompt, fields kept, env-name override, no overwrite, validation
	n = f.approvals.Load()
	cr, err := f.cli.Copy(ctx, wire.CopyArgs{Pairs: []wire.CopyPair{{Src: "s/a", Dst: "t/a2"}, {Src: "s/w", Dst: "t/w2"}}, EnvName: "NEW_TOK"})
	if err != nil || len(cr.Names) != 2 || f.approvals.Load() != n+1 {
		t.Fatalf("%+v %v approvals=%d", cr, err, f.approvals.Load()-n)
	}
	if r, _ := f.cli.Same(ctx, []string{"s/a", "t/a2"}); r.Items[0].Status != "same" {
		t.Fatal("copied value must equal source")
	}
	l, _ := f.cli.List(ctx)
	found := map[string]api.SecretInfo{}
	for _, s := range l {
		found[s.Name] = s
	}
	if found["t/w2"].Kind != "oracle-wallet" || found["t/w2"].Env != "test" {
		t.Fatalf("metadata not copied: %+v", found)
	}
	if _, err := f.cli.Copy(ctx, wire.CopyArgs{Pairs: []wire.CopyPair{{Src: "s/a", Dst: "s/b"}}}); code(err) != wire.CodeBadRequest {
		t.Fatalf("overwrite must be refused: %v", err)
	}
	if _, err := f.cli.Copy(ctx, wire.CopyArgs{Pairs: []wire.CopyPair{{Src: "s/a", Dst: "x/1"}, {Src: "s/b", Dst: "x/1"}}}); code(err) != wire.CodeBadRequest {
		t.Fatalf("duplicate dst: %v", err)
	}
	if _, err := f.cli.Copy(ctx, wire.CopyArgs{Pairs: []wire.CopyPair{{Src: "s/a", Dst: "x/ok"}}, EnvName: "PATH"}); code(err) != wire.CodeBadRequest {
		t.Fatalf("loader env name: %v", err)
	}
	f.refuse.Store(true)
	if _, err := f.cli.Copy(ctx, wire.CopyArgs{Pairs: []wire.CopyPair{{Src: "s/a", Dst: "x/ok"}}}); code(err) != wire.CodeDenied {
		t.Fatalf("copy needs approval: %v", err)
	}
	if l, _ := f.cli.List(ctx); len(l) != 6 {
		t.Fatalf("nothing else may be created: %d", len(l))
	}
}

// A locked workstation must not change anything for the agent: IdleLock=0 and
// LockOnScreenLock=false never lock the vault, however long the clock runs.
func TestNoAutoLockByDefault(t *testing.T) {
	var offset atomic.Int64
	start := time.Now()
	f := newFixtureWith(t, 0, 10*time.Millisecond, func(c *Config) {
		c.LockOnScreenLock = false
		c.Now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	})
	f.locked.Store(true)
	offset.Store(int64(2 * time.Hour))
	time.Sleep(300 * time.Millisecond)
	if f.b.Locked() {
		t.Fatal("vault auto-locked with IdleLock=0 and LockOnScreenLock=false")
	}
	st, err := f.cli.Status(context.Background())
	if err != nil || !st.Unlocked || st.LockAfter != "" {
		t.Fatalf("status %+v %v", st, err)
	}
}

// A refused start-up Hello leaves the broker running and locked (tray mode), not exited.
func TestStartupRefusedStaysUp(t *testing.T) {
	f := newFixtureWith(t, 0, time.Hour, func(c *Config) {
		c.Approver = approve.Func(func(context.Context, string) error { return errors.New("hủy") })
	})
	st, err := f.cli.Status(context.Background())
	if err != nil || st.Unlocked || f.b.UIState() != (UIState{}) {
		t.Fatalf("status %+v %v", st, err)
	}
}

// ---- durable grants (B) ----

// helperRun puts a secret and a policy that allows the test binary itself (hash pinned) with
// user-presence approval, and returns a run request for it.
func helperRun(t *testing.T, f *fixture, extra string) api.RunRequest {
	t.Helper()
	f.withStore(func(st *store.Store) {
		if _, err := st.Put("", record.Plain{Name: "ebs/test/tok", Value: "s3cr3t-Value-ABC123xyz", Env: "test", Kind: "env", EnvName: "MY_TOKEN"}); err != nil {
			t.Fatal(err)
		}
	})
	exe, _ := filepath.Abs(os.Args[0])
	exeHash, err := allowlist.FileHash(exe)
	if err != nil {
		t.Fatal(err)
	}
	f.policy(`grants:
  ebs/test/tok:
    allow_commands: ["\"`+filepath.ToSlash(exe)+`\" `+exeHash+` -test.run=TestBrokerHelper"]
    approval: user-presence
`+extra, true)
	t.Setenv("KG_BROKER_HELPER", "1")
	t.Setenv("KG_HELPER_VAR", "MY_TOKEN")
	if _, err := f.cli.List(context.Background()); err != nil { // unlock now: tests count only grant prompts
		t.Fatal(err)
	}
	return api.RunRequest{Secrets: []string{"ebs/test/tok"}, Argv: []string{exe, "-test.run=TestBrokerHelper"}, Agent: "t"}
}

func (f *fixture) mustRun(req api.RunRequest) {
	f.t.Helper()
	var out bytes.Buffer
	if code, err := f.cli.Run(context.Background(), req, &out, &out); err != nil || code != 0 {
		f.t.Fatalf("run: %d %v\n%s", code, err, out.String())
	}
}

// restart stops the broker and starts a new one on the same KG_HOME (as after a reboot).
func (f *fixture) restart() {
	f.t.Helper()
	f.cancel()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(SockPath(f.home)); err != nil && f.b.Locked() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	b, err := New(f.cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	f.b = b
	f.start()
	f.b.endSession("test") // the start-up Hello opened a session; these tests are about no-session behaviour
}

func TestDurableGrantSurvives(t *testing.T) {
	f := newFixture(t, 0, time.Hour)
	req := helperRun(t, f, "")
	ctx := context.Background()

	n := f.approvals.Load()
	f.mustRun(req)
	if f.approvals.Load() != n+1 {
		t.Fatalf("first run must ask once, asked %d", f.approvals.Load()-n)
	}
	gv, err := f.cli.Grants(ctx)
	if err != nil || len(gv) != 1 || !gv[0].Durable || gv[0].By != "hello" || gv[0].Expires != nil || gv[0].Path == "" {
		t.Fatalf("grants: %+v %v", gv, err)
	}
	if _, err := os.Stat(filepath.Join(f.home, "state", "grants.json")); err != nil {
		t.Fatal(err)
	}

	// Lock + unlock: only the unlock prompt.
	f.b.Lock()
	n = f.approvals.Load()
	f.mustRun(req)
	if f.approvals.Load() != n+1 {
		t.Fatalf("after lock: want the unlock prompt only, got %d", f.approvals.Load()-n)
	}

	// Session start/end does not forget it.
	if err := f.cli.SessionStart(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.cli.SessionEnd(ctx); err != nil {
		t.Fatal(err)
	}
	n = f.approvals.Load()
	f.mustRun(req)
	if f.approvals.Load() != n {
		t.Fatalf("after session end: no prompt expected, got %d", f.approvals.Load()-n)
	}

	// A new broker on the same KG_HOME (restart) still has it.
	f.restart()
	n = f.approvals.Load()
	f.mustRun(req)
	if f.approvals.Load() != n {
		t.Fatalf("after restart: no prompt expected, got %d", f.approvals.Load()-n)
	}
}

func TestSessionGrantNotDurable(t *testing.T) {
	f := newFixture(t, 0, time.Hour)
	req := helperRun(t, f, "")
	ctx := context.Background()
	if err := f.cli.SessionStart(ctx); err != nil {
		t.Fatal(err)
	}
	n := f.approvals.Load()
	f.mustRun(req)
	if f.approvals.Load() != n {
		t.Fatal("no prompt expected in a session")
	}
	gv, _ := f.cli.Grants(ctx)
	if len(gv) != 1 || gv[0].Durable || gv[0].By != "session" {
		t.Fatalf("grants: %+v", gv)
	}
	if _, err := os.Stat(filepath.Join(f.home, "state", "grants.json")); err == nil {
		t.Fatal("session grant must not be written to disk")
	}
	if err := f.cli.SessionEnd(ctx); err != nil {
		t.Fatal(err)
	}
	if gv, _ := f.cli.Grants(ctx); len(gv) != 0 {
		t.Fatalf("session grant must vanish at session end: %+v", gv)
	}
	f.mustRun(req)
	if f.approvals.Load() != n+1 {
		t.Fatal("prompt expected after session end")
	}
}

func TestGrantsFileTamper(t *testing.T) {
	f := newFixture(t, 0, time.Hour)
	req := helperRun(t, f, "")
	f.mustRun(req)
	p := filepath.Join(f.home, "state", "grants.json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// untouched file loads
	f.restart()
	if gv, _ := f.cli.Grants(context.Background()); len(gv) != 1 {
		t.Fatalf("valid file must load: %+v", gv)
	}
	bad := bytes.Replace(data, []byte(`"hello"`), []byte(`"hellp"`), 1)
	if bytes.Equal(bad, data) {
		t.Fatal("tamper had no effect")
	}
	if err := os.WriteFile(p, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	f.restart()
	if gv, _ := f.cli.Grants(context.Background()); len(gv) != 0 {
		t.Fatalf("tampered file must drop every grant: %+v", gv)
	}
	if !strings.Contains(f.prompt.String(), "grants.json không hợp lệ") {
		t.Fatal("expected a log line about grants.json")
	}
	n := f.approvals.Load()
	f.mustRun(req)
	if f.approvals.Load() != n+1 {
		t.Fatal("prompt expected after a rejected grants.json")
	}
}

func TestPolicyApplyDropsRemovedAllowCommands(t *testing.T) {
	f := newFixture(t, 0, time.Hour)
	f.put("", "ebs/test/a", "test")
	ctx := context.Background()
	f.policy(basePolicy, false)
	if _, err := f.cli.PolicyApply(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); err != nil {
		t.Fatal(err)
	}
	if gv, _ := f.cli.Grants(ctx); len(gv) != 1 {
		t.Fatalf("grant expected: %+v", gv)
	}
	f.policy(strings.Replace(basePolicy, `["sql /@HTTEST"]`, `["sql /@HTTEST2"]`, 1), false)
	if _, err := f.cli.PolicyApply(ctx); err != nil {
		t.Fatal(err)
	}
	if gv, _ := f.cli.Grants(ctx); len(gv) != 0 {
		t.Fatalf("grant of a removed allow_commands entry must be dropped: %+v", gv)
	}
	data, _ := os.ReadFile(filepath.Join(f.home, "state", "grants.json"))
	if strings.Contains(string(data), "HTTEST") {
		t.Fatalf("grants.json must be rewritten: %s", data)
	}
}

func TestGrantsRevoke(t *testing.T) {
	f := newFixture(t, 0, time.Hour)
	req := helperRun(t, f, "")
	ctx := context.Background()
	f.mustRun(req)
	n := f.approvals.Load()
	if c, err := f.cli.GrantsRevoke(ctx, "ebs/test/other", false); err != nil || c != 0 {
		t.Fatalf("revoke other: %d %v", c, err)
	}
	if c, err := f.cli.GrantsRevoke(ctx, "ebs/test/tok", false); err != nil || c != 1 {
		t.Fatalf("revoke: %d %v", c, err)
	}
	if gv, _ := f.cli.Grants(ctx); len(gv) != 0 {
		t.Fatalf("grants after revoke: %+v", gv)
	}
	f.mustRun(req)
	if f.approvals.Load() != n+1 {
		t.Fatal("prompt expected after revoke")
	}
	if c, err := f.cli.GrantsRevoke(ctx, "", true); err != nil || c != 1 {
		t.Fatalf("revoke all: %d %v", c, err)
	}
	if _, err := f.cli.GrantsRevoke(ctx, "", false); code(err) != wire.CodeBadRequest {
		t.Fatalf("revoke needs a target: %v", err)
	}
	// revoking while locked works without a prompt and survives a restart
	f.mustRun(req)
	f.b.Lock()
	n = f.approvals.Load()
	if c, err := f.cli.GrantsRevoke(ctx, "ebs/test/tok", false); err != nil || c != 1 || f.approvals.Load() != n {
		t.Fatalf("revoke while locked: %d %v", c, err)
	}
	f.restart()
	if gv, _ := f.cli.Grants(ctx); len(gv) != 0 {
		t.Fatalf("revoked grant came back: %+v", gv)
	}
}

func TestPolicyTTLStillHonoured(t *testing.T) {
	f := newFixture(t, 0, time.Hour)
	f.put("", "ebs/test/a", "test")
	f.policy(strings.Replace(basePolicy, "ttl: 10m", "ttl: 1s", 1), true)
	ctx := context.Background()
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); err != nil {
		t.Fatal(err)
	}
	gv, _ := f.cli.Grants(ctx)
	if len(gv) != 1 || gv[0].Expires == nil {
		t.Fatalf("ttl grant must expire: %+v", gv)
	}
	n := f.approvals.Load()
	time.Sleep(1300 * time.Millisecond)
	if _, err := f.cli.RequestGrant(ctx, "ebs/test/a", sqlArgv, "t"); err != nil || f.approvals.Load() != n+1 {
		t.Fatalf("expired grant must be asked again: %v", err)
	}
}

// Locking the workstation changes nothing for the agent: no prompt, in a session or with a durable grant.
func TestScreenLockKeepsAgentWorking(t *testing.T) {
	f := newFixtureWith(t, 0, 20*time.Millisecond, func(c *Config) { c.LockOnScreenLock = false })
	req := helperRun(t, f, "")
	ctx := context.Background()

	// (a) work session
	if err := f.cli.SessionStart(ctx); err != nil {
		t.Fatal(err)
	}
	f.locked.Store(true)
	time.Sleep(200 * time.Millisecond)
	n := f.approvals.Load()
	f.mustRun(req)
	if f.approvals.Load() != n || f.b.Locked() {
		t.Fatalf("session + locked screen: approvals +%d, locked=%v", f.approvals.Load()-n, f.b.Locked())
	}
	f.locked.Store(false)
	if err := f.cli.SessionEnd(ctx); err != nil {
		t.Fatal(err)
	}

	// (b) no session, durable grant
	f.mustRun(req) // asks once and remembers
	f.locked.Store(true)
	time.Sleep(200 * time.Millisecond)
	n = f.approvals.Load()
	f.mustRun(req)
	if f.approvals.Load() != n || f.b.Locked() {
		t.Fatalf("durable grant + locked screen: approvals +%d, locked=%v", f.approvals.Load()-n, f.b.Locked())
	}
	for _, e := range auditEvents(t, f) {
		if e == "deny" {
			t.Fatal("audit must not contain a deny")
		}
	}
}

func auditEvents(t *testing.T, f *fixture) []string {
	t.Helper()
	data, _ := os.ReadFile(filepath.Join(f.home, "audit", "ledger.jsonl"))
	var evs []string
	for _, l := range bytes.Split(data, []byte("\n")) {
		var e struct {
			Event string `json:"event"`
		}
		if json.Unmarshal(l, &e) == nil && e.Event != "" {
			evs = append(evs, e.Event)
		}
	}
	return evs
}

func TestStartupLockedReportsRefusal(t *testing.T) {
	got := make(chan error, 1)
	refusal := fmt.Errorf("%w (NotConfiguredForUser): %s", approve.ErrNotVerified, approve.HelloHint("NotConfiguredForUser"))
	f := newFixtureWith(t, 0, 0, func(c *Config) {
		c.Approver = approve.Func(func(context.Context, string) error { return refusal })
		c.OnStartupLocked = func(err error) { got <- err }
	})
	select {
	case err := <-got:
		if !errors.Is(err, approve.ErrNotVerified) || !strings.Contains(err.Error(), "ms-settings:signinoptions") {
			t.Fatalf("startup refusal lost its reason: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OnStartupLocked not called")
	}
	if f.b.UIState().Unlocked {
		t.Fatal("broker must stay locked")
	}
}

func TestStartupUnlockedDoesNotReportLocked(t *testing.T) {
	got := make(chan error, 1)
	f := newFixtureWith(t, 0, 0, func(c *Config) { c.OnStartupLocked = func(err error) { got <- err } })
	<-f.b.startupDone
	select {
	case err := <-got:
		t.Fatalf("unexpected OnStartupLocked: %v", err)
	default:
	}
}
