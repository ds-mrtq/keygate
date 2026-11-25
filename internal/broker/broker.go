// Package broker is the long-lived process that holds the vault key in RAM, enforces policy,
// grants, approvals and redaction, and serves the newline-JSON socket protocol (DESIGN sec 9).
// No secret value ever crosses the socket: set/import/reveal use the broker's own terminal.
package broker

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"keygate/internal/allowlist"
	"keygate/internal/api"
	"keygate/internal/approve"
	"keygate/internal/audit"
	"keygate/internal/broker/wire"
	"keygate/internal/devkey"
	"keygate/internal/execwrap"
	"keygate/internal/members"
	"keygate/internal/policy"
	"keygate/internal/remote"
	"keygate/internal/store"
	"keygate/internal/tty"
)

// DefaultIdleLock is the auto-lock delay.
const DefaultIdleLock = 15 * time.Minute

// SockName is the socket file inside KG_HOME.
const SockName = "broker.sock"

// DefaultRevealCooldown blocks reveal prompts for a while after a refusal.
const DefaultRevealCooldown = 60 * time.Second

// Prompter is the broker's own terminal or dialogs (never the socket).
type Prompter interface {
	ReadLine(ctx context.Context, prompt string) (string, error)
	// ReadSecret reads without echo when the terminal allows it.
	ReadSecret(ctx context.Context, prompt string) (string, error)
	// ShowSecret displays a revealed value to the user at this machine.
	ShowSecret(ctx context.Context, name, value string) error
	// Review lets the user read a long text before approving; nil = continue.
	Review(ctx context.Context, title, text string) error
	Out() io.Writer
}

// Config wires the broker; zero values get production defaults.
type Config struct {
	Home     string
	Approver approve.Approver // user-presence; default approve.Platform()
	Prompt   Prompter         // broker TTY; default the process stdin/stderr
	// Password asks for the device unlock password (Linux file backend); default prompts on Prompt.
	Password devkey.PasswordFunc
	// CheckPassword verifies a device unlock password typed for an approval on a system without
	// user-presence; default (Linux file backend) decrypts device.key.enc with it.
	CheckPassword func(password string) error
	// Keys opens the device key store; default devkey.Open(Home, ...).
	Keys     func() (devkey.Store, error)
	IdleLock time.Duration // 0 = never auto-lock when idle (the default); only a negative value means DefaultIdleLock
	// LockOnScreenLock locks the vault when the workstation locks (outside a work session). Off by default.
	LockOnScreenLock bool
	ScreenPoll       time.Duration
	ScreenLocked     func() bool // default: ScreenLocked (Windows session lock flag)
	RevealCooldown   time.Duration
	Now              func() time.Time
	// OnChange is called after the lock state, the session or the pending count changed.
	OnChange func()
	// OnPrompt is called just before a user-presence prompt (Windows Hello) is shown.
	OnPrompt func(text string)
	// OnStartupLocked is called when the start-up unlock is refused and the broker stays locked.
	OnStartupLocked func(err error)
	// ApprovalWait bounds how long one request waits for a human before the client gets `pending`
	// (default 270s, below the 300s limit of agent tools).
	ApprovalWait time.Duration
	// RemoteDelay is how long the local prompt (Hello) has to itself before the request is also
	// published to the phone (default 15s). A locked screen publishes at once.
	RemoteDelay time.Duration
	// PendingTTL is how long a published request stays open on the phone (default 30m).
	PendingTTL time.Duration
	// PreapprovalTTL is how long a decision made after the caller left stays usable for a re-run (default 10m).
	PreapprovalTTL time.Duration
	// MaxMsgAge rejects phone messages older than this (default 10m).
	MaxMsgAge time.Duration
	// MaxPending caps simultaneously open phone requests (default 20).
	MaxPending int
	// Mailbox opens the relay channel to approver devices; default: relay client when vault.json has
	// relay_url, else none. May return nil.
	Mailbox func(cfg store.VaultConfig, id *store.Identity) Mailbox
	// Remote loop cadence (defaults 3s while a request is open or the phone is active, 15s otherwise,
	// at least 2s between two view posts, a heartbeat view every 60s).
	RemoteFast, RemoteSlow, RemoteMinPost, RemoteBeat time.Duration
}

// session is the unlocked state; dropped on lock.
type session struct {
	st  *store.Store
	led *audit.Ledger
}

// grantKey identifies a grant: secret, policy entry, resolved program and canonical run directory.
type grantKey struct{ secret, pattern, path, dir string }

// Broker is the running service.
type Broker struct {
	cfg Config

	pwFailures atomic.Int64 // wrong device passwords typed for approvals since start

	mu           sync.Mutex
	sess         *session
	lastUse      time.Time
	grants       map[grantKey]grantEntry
	vaultID      string     // from vault.json, set by Serve
	grantsFileMu sync.Mutex // serializes grants.json writes
	dev, vlt     string
	lastSync     *time.Time
	pcache       *policyView
	polMax       uint64 // highest policy version seen (RAM only)
	revealBlock  time.Time
	unlockMu     sync.Mutex    // serializes unlock prompts
	apprSem      chan struct{} // capacity 1: one local human prompt at a time
	ownerMu      sync.Mutex    // serializes owner operations from the tray (add/revoke device)
	ownerWrite   sync.Mutex    // held while an owner operation writes; Lock waits for it (never held during a prompt)

	rmu          sync.Mutex // guards everything below (phone approval engine and remote loop)
	mailbox      Mailbox
	pending      map[string]*pendingReq
	preapproved  map[string]preapproval
	mstate       *members.State // membership as of the last verified unlock (RAM only)
	markCount    uint64         // membership position already MAC'd in state/members.mac
	markHead     string
	results      []remote.CmdResult
	seen         map[string]time.Time
	dirty        bool
	pushNext     bool
	fastUntil    time.Time
	rview        viewCache
	kick         chan struct{}
	onListen     func()
	policyLoadMu sync.Mutex
	sessID       string // non-empty while a work session is open
	sessStart    time.Time
	id           *store.Identity // device identity, loaded once by Serve and kept for the process lifetime
	started      time.Time
	startupDone  chan struct{} // closed when the start-up unlock attempt finished
}

// New validates cfg and applies defaults.
func New(cfg Config) (*Broker, error) {
	if cfg.Home == "" {
		return nil, errors.New("broker: thiếu Home")
	}
	if cfg.Approver == nil {
		cfg.Approver = approve.Platform()
	}
	if cfg.IdleLock < 0 {
		cfg.IdleLock = DefaultIdleLock
	}
	if cfg.ScreenPoll <= 0 {
		cfg.ScreenPoll = 5 * time.Second
	}
	if cfg.ScreenLocked == nil {
		cfg.ScreenLocked = ScreenLocked
	}
	if cfg.RevealCooldown <= 0 {
		cfg.RevealCooldown = DefaultRevealCooldown
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&cfg.ApprovalWait, 270*time.Second)
	def(&cfg.RemoteDelay, 15*time.Second)
	def(&cfg.PendingTTL, 30*time.Minute)
	def(&cfg.PreapprovalTTL, 10*time.Minute)
	def(&cfg.MaxMsgAge, 10*time.Minute)
	def(&cfg.RemoteFast, 3*time.Second)
	def(&cfg.RemoteSlow, 15*time.Second)
	def(&cfg.RemoteMinPost, 2*time.Second)
	def(&cfg.RemoteBeat, 60*time.Second)
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 20
	}
	if cfg.Mailbox == nil {
		cfg.Mailbox = defaultMailbox
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Prompt == nil {
		cfg.Prompt = tty.Stdin()
	}
	b := &Broker{cfg: cfg, grants: map[grantKey]grantEntry{}, startupDone: make(chan struct{}),
		apprSem: make(chan struct{}, 1), pending: map[string]*pendingReq{}, preapproved: map[string]preapproval{},
		seen: map[string]time.Time{}, kick: make(chan struct{}, 1)}
	if cfg.Password == nil {
		b.cfg.Password = func(confirm bool) (string, error) {
			p, err := cfg.Prompt.ReadSecret(context.Background(), "Mật khẩu mở khóa thiết bị: ")
			if err != nil || !confirm {
				return p, err
			}
			p2, err := cfg.Prompt.ReadSecret(context.Background(), "Nhập lại: ")
			if err != nil {
				return "", err
			}
			if p != p2 {
				return "", errors.New("hai lần nhập không khớp")
			}
			return p, nil
		}
	}
	if cfg.Keys == nil {
		b.cfg.Keys = func() (devkey.Store, error) {
			return devkey.Open(cfg.Home, devkey.Options{Password: b.cfg.Password})
		}
	}
	return b, nil
}

// OnListen registers a callback invoked once the socket accepts connections (tests, readiness).
func (b *Broker) OnListen(f func()) { b.onListen = f }

// SockPath returns the socket path for home.
func SockPath(home string) string { return filepath.Join(home, SockName) }

// RunDir is where plaintext temp material lives (0700, swept at start).
func RunDir(home string) string { return filepath.Join(home, "run") }

func (b *Broker) out() io.Writer { return b.cfg.Prompt.Out() }

func (b *Broker) logf(format string, a ...any) { fmt.Fprintf(b.out(), "[broker] "+format+"\n", a...) }

// touch resets the idle timer. Only human-approved actions and authorized runs call it.
func (b *Broker) touch() {
	b.mu.Lock()
	b.lastUse = b.cfg.Now()
	b.mu.Unlock()
}

// Unlock opens the vault after human approval; no-op when already unlocked.
func (b *Broker) Unlock(ctx context.Context) error {
	_, err := b.session(ctx)
	return err
}

func (b *Broker) session(ctx context.Context) (*session, error) {
	b.mu.Lock()
	s := b.sess
	b.mu.Unlock()
	if s != nil {
		return s, nil
	}
	b.unlockMu.Lock()
	defer b.unlockMu.Unlock()
	b.mu.Lock()
	if b.sess != nil {
		s = b.sess
		b.mu.Unlock()
		return s, nil
	}
	b.mu.Unlock()

	res, err := b.humanApprove(ctx, nil, approvalReq{op: "unlock", command: "mở khóa vault KeyGate", mode: policy.ApprovalUserPresence, session: true})
	if err != nil {
		if isPending(err) {
			return nil, err
		}
		if !errors.Is(err, approve.ErrUnsupported) {
			return nil, fmt.Errorf("mở khóa bị từ chối: %w", err)
		}
		// No user-presence on this OS: the device password prompt (devkey) is the gate.
	}
	s, err = b.openStore()
	if err != nil {
		return nil, err
	}
	if res.choice == "session" {
		b.openSession(s, res.by)
	}
	return s, nil
}

// openStore opens the vault with the process identity (the approval already happened) and makes it
// the live session. The caller holds unlockMu.
func (b *Broker) openStore() (*session, error) {
	id := b.id
	if id == nil {
		return nil, errors.New("broker chưa nạp khóa thiết bị")
	}
	st, err := store.Open(b.cfg.Home, id)
	if err != nil {
		return nil, err
	}
	s := &session{st: st, led: audit.Open(filepath.Join(b.cfg.Home, "audit", "ledger.jsonl"),
		filepath.Join(b.cfg.Home, "state", "audit.head"), st.LocalMacKey())}
	b.mu.Lock()
	b.sess, b.lastUse = s, b.cfg.Now()
	b.dev, b.vlt = id.Dev, st.Vault()
	b.mu.Unlock()
	b.refreshMembers(s)
	b.logf("đã mở khóa (thiết bị %s)", id.Dev)
	b.changed()
	return s, nil
}

// Lock drops the vault key, releases KG_HOME/lock and forgets every grant.
func (b *Broker) Lock() {
	b.ownerWrite.Lock() // an owner operation in its write phase finishes first: never close the store under it
	defer b.ownerWrite.Unlock()
	b.mu.Lock()
	s := b.sess
	b.sess = nil
	b.dropVolatileGrants()
	b.pcache = nil
	b.sessID = ""
	b.mu.Unlock()
	if s != nil {
		s.st.Close()
		b.logf("đã khóa")
	}
	b.changed()
}

// SessionOpen reports whether a work session is open.
func (b *Broker) SessionOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sessID != ""
}

// openSession starts a work session (the caller already obtained a human approval).
func (b *Broker) openSession(s *session, peer string) string {
	id := "ses_" + strings.ToLower(rand.Text())[:10]
	b.mu.Lock()
	b.sessID, b.sessStart = id, b.cfg.Now()
	b.dropVolatileGrants()
	b.mu.Unlock()
	b.audBest(s, audit.Entry{Event: audit.EvSession, Approval: "start", Session: id, Peer: peer})
	b.logf("phiên làm việc %s đã mở: grant user-presence/device tự cấp, không tự khóa (kg session end để kết thúc)", id)
	b.changed()
	return id
}

// endSession closes the work session and forgets every grant (session grants must not outlive it).
func (b *Broker) endSession(peer string) {
	b.mu.Lock()
	id, s := b.sessID, b.sess
	b.sessID = ""
	b.dropVolatileGrants()
	b.mu.Unlock()
	if id != "" {
		if s != nil {
			b.audBest(s, audit.Entry{Event: audit.EvSession, Approval: "end", Session: id, Peer: peer})
		}
		b.logf("phiên làm việc %s đã kết thúc", id)
		b.changed()
	}
}

// Locked reports whether the vault key is absent.
func (b *Broker) Locked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sess == nil
}

func (b *Broker) watch(ctx context.Context) {
	t := time.NewTicker(b.cfg.ScreenPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.mu.Lock()
			inSession := b.sessID != ""
			idle := b.cfg.IdleLock > 0 && b.sess != nil && b.cfg.Now().Sub(b.lastUse) >= b.cfg.IdleLock
			b.mu.Unlock()
			if inSession {
				continue // a work session disables idle and screen-lock auto-lock
			}
			if idle || (b.cfg.LockOnScreenLock && !b.Locked() && b.cfg.ScreenLocked()) {
				b.Lock()
			}
		}
	}
}

// UIState is the snapshot the tray icon shows.
type UIState struct {
	Unlocked, Session bool
	Pending           int
}

// UIState returns the current lock/session state and the number of requests published to the phone.
func (b *Broker) UIState() UIState {
	n := b.publishedCount()
	b.mu.Lock()
	defer b.mu.Unlock()
	return UIState{Unlocked: b.sess != nil, Session: b.sessID != "", Pending: n}
}

// changed tells the UI and the phone that the lock state, the session, the grants or the pending
// set changed.
func (b *Broker) changed() {
	b.markDirty()
	if b.cfg.OnChange != nil {
		b.cfg.OnChange()
	}
}

// StartSession opens a work session (unlocking first if needed; the unlock approval doubles as the
// session approval, otherwise one user-presence prompt is shown).
func (b *Broker) StartSession(ctx context.Context, peer string) error {
	if b.SessionOpen() {
		return nil
	}
	wasLocked := b.Locked()
	s, err := b.session(ctx)
	if err != nil {
		var ce *cmdErr
		if errors.As(err, &ce) {
			return err
		}
		return fail(wire.CodeLocked, "%v", err)
	}
	if !wasLocked {
		if _, err := b.humanApprove(ctx, s, approvalReq{op: "session", mode: policy.ApprovalUserPresence, peer: peer,
			command: "MỞ phiên làm việc (grant user-presence/device tự cấp, không tự khóa)"}); err != nil {
			return refused(err, "mở phiên")
		}
	}
	b.openSession(s, peer)
	return nil
}

// EndSession closes the work session (no prompt: it only reduces authority).
func (b *Broker) EndSession(peer string) { b.endSession(peer) }

// SetFromUI stores a secret whose value the broker's own GUI collected. Overwriting an existing
// secret needs a user-presence approval at this machine.
func (b *Broker) SetFromUI(ctx context.Context, r api.SetRequest, value string) error {
	s, err := b.session(ctx)
	if err != nil {
		return err
	}
	r.Value = ""
	if err := b.validateSet(&r); err != nil {
		return err
	}
	if value == "" {
		return fail(wire.CodeBadRequest, "giá trị rỗng")
	}
	if b.exists(s, r.Name) {
		if _, err := b.humanApprove(ctx, s, approvalReq{op: "overwrite", secrets: []string{r.Name}, localOnly: true, peer: "khay hệ thống",
			command: "GHI ĐÈ secret đã có", mode: policy.ApprovalUserPresence}); err != nil {
			return refused(err, "ghi đè")
		}
	}
	return b.storeSecret(s, r, value, audit.EvSet, "", "tray")
}

// startupUnlock is the unlock attempted at start; the Hello approval also opens the work session.
// A refusal leaves the broker running and locked.
func (b *Broker) startupUnlock(ctx context.Context) {
	defer close(b.startupDone)
	s, err := b.session(ctx)
	if err != nil {
		b.logf("chưa mở khóa: %v", err)
		if b.cfg.OnStartupLocked != nil && !isPending(err) {
			b.cfg.OnStartupLocked(err)
		}
		return
	}
	b.openSession(s, "broker-start") // the start-up unlock approval also opens the session
}

// Serve sweeps leftovers, listens on KG_HOME/broker.sock and serves until ctx is cancelled. The
// start-up unlock runs in the background: the broker stays up (locked) when it is refused.
func (b *Broker) Serve(ctx context.Context) error {
	if err := execwrap.Sweep(RunDir(b.cfg.Home)); err != nil {
		return fmt.Errorf("dọn thư mục run: %w", err)
	}
	ks, err := b.cfg.Keys()
	if err != nil {
		return err
	}
	id, err := store.LoadIdentity(b.cfg.Home, ks)
	if err != nil {
		return fmt.Errorf("nạp khóa thiết bị: %w", err)
	}
	if b.cfg.CheckPassword == nil && ks.Name() == "file" {
		b.cfg.CheckPassword = filePasswordCheck(b.cfg.Home, id.Dev)
	}
	b.mu.Lock()
	b.id, b.started = id, b.cfg.Now()
	b.mu.Unlock()
	cfg, err := store.ReadConfig(b.cfg.Home)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.vaultID = cfg.Vault
	b.mu.Unlock()
	if b.cfg.Mailbox != nil {
		b.rmu.Lock()
		b.mailbox = b.cfg.Mailbox(cfg, id)
		b.rmu.Unlock()
	}
	b.loadGrants()
	b.loadMembers()
	sock := SockPath(b.cfg.Home)
	if c, err := net.DialTimeout("unix", sock, time.Second); err == nil {
		c.Close()
		return errors.New("broker đã chạy trên " + sock)
	}
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("mở socket %s: %w", sock, err)
	}
	os.Chmod(sock, 0o600)
	defer func() {
		ln.Close()
		os.Remove(sock)
		execwrap.CleanupAll()
		b.Lock()
	}()
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }() // stop and drain the remote loop and the connections before the vault is locked
	go func() { <-ctx.Done(); ln.Close() }()
	go b.watch(ctx)
	go b.startupUnlock(ctx)
	if b.mailbox != nil {
		wg.Add(1)
		go func() { defer wg.Done(); b.remoteLoop(ctx) }()
	}
	go func() {
		<-b.startupDone
		if b.onListen != nil {
			b.onListen()
		}
	}()
	if b.cfg.IdleLock > 0 || b.cfg.LockOnScreenLock {
		b.logf("lắng nghe %s (tự khóa: rảnh %s, khóa màn hình %v)", sock, b.cfg.IdleLock, b.cfg.LockOnScreenLock)
	} else {
		b.logf("lắng nghe %s (không tự khóa)", sock)
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.handleConn(ctx, c)
		}()
	}
}

type respWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (w *respWriter) frame(f wire.Frame) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enc.Encode(f)
}

func (w *respWriter) ok(v any) {
	var raw json.RawMessage
	if v != nil {
		raw, _ = json.Marshal(v)
	}
	w.frame(wire.Frame{T: wire.FrameOK, Data: raw})
}

type streamWriter struct {
	w      *respWriter
	stream string
}

func (s streamWriter) Write(p []byte) (int, error) {
	s.w.frame(wire.Frame{T: wire.FrameOut, Stream: s.stream, Chunk: append([]byte(nil), p...)})
	return len(p), nil
}

const maxRequest = 1 << 20

func (b *Broker) handleConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	peer := peerInfo(c)
	w := &respWriter{enc: json.NewEncoder(c)}
	br := bufio.NewReaderSize(c, 64<<10)
	line, err := readLine(br, maxRequest)
	if err != nil {
		return
	}
	var req wire.Request
	if err := json.Unmarshal(line, &req); err != nil {
		w.frame(wire.Frame{T: wire.FrameErr, Code: wire.CodeBadRequest, Msg: "yêu cầu không phải JSON"})
		return
	}
	rctx, cancel := context.WithCancel(withNote(ctx, func(msg string) { w.frame(wire.Frame{T: wire.FrameNote, Msg: msg}) }))
	defer cancel()
	go func() { // client gone => cancel the work (kills the child)
		io.Copy(io.Discard, br)
		cancel()
	}()
	if err := b.dispatch(rctx, req, w, peer); err != nil {
		code, msg := classify(err)
		w.frame(wire.Frame{T: wire.FrameErr, Code: code, Msg: msg})
	}
}

func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > limit {
			return nil, errors.New("yêu cầu quá lớn")
		}
		if !isPrefix {
			return out, nil
		}
	}
}

// policyView is a verified policy plus the program paths resolved ONCE for its entries.
type policyView struct {
	L   *policy.Loaded
	res map[string][]allowlist.Resolved // grant pattern -> resolved entries
}

// loadPolicy verifies the pin (MAC, hash, monotonic version) and resolves allow_commands with the
// broker's own PATH the first time a given policy version is seen after start/apply.
func (b *Broker) loadPolicy(s *session) (*policyView, error) {
	b.policyLoadMu.Lock()
	defer b.policyLoadMu.Unlock()
	l, err := policy.LoadVerified(filepath.Join(b.cfg.Home, "policy.yaml"), filepath.Join(b.cfg.Home, "state", "policy.pin"), s.st.LocalMacKey())
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	if l.Version < b.polMax {
		b.mu.Unlock()
		return nil, fmt.Errorf("%w: pin phiên bản %d < đã thấy %d (nghi khôi phục policy cũ)", policy.ErrPinMismatch, l.Version, b.polMax)
	}
	b.polMax = l.Version
	pc := b.pcache
	b.mu.Unlock()
	if pc != nil && pc.L.Hash == l.Hash && pc.L.Version == l.Version {
		return pc, nil
	}
	pv := &policyView{L: l, res: map[string][]allowlist.Resolved{}}
	for _, g := range l.Policy.Grants {
		pv.res[g.Pattern] = allowlist.Resolve(g.Entries)
	}
	b.mu.Lock()
	b.pcache = pv
	b.mu.Unlock()
	return pv, nil
}

// lockAfter is the idle auto-lock delay shown by `kg status` ("" = never).
func lockAfter(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}
