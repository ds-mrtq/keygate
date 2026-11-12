package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"keygate/internal/allowlist"
	"keygate/internal/api"
	"keygate/internal/approve"
	"keygate/internal/audit"
	"keygate/internal/broker/wire"
	"keygate/internal/channel"
	"keygate/internal/envname"
	"keygate/internal/execwrap"
	"keygate/internal/fsx"
	"keygate/internal/importer"
	"keygate/internal/policy"
	"keygate/internal/record"
	"keygate/internal/redact"
	"keygate/internal/store"
)

type cmdErr struct{ code, msg string }

func (e *cmdErr) Error() string { return e.msg }

func fail(code, format string, a ...any) error { return &cmdErr{code, fmt.Sprintf(format, a...)} }

func classify(err error) (string, string) {
	var ce *cmdErr
	switch {
	case errors.As(err, &ce):
		return ce.code, ce.msg
	case errors.Is(err, store.ErrConflict):
		return wire.CodeConflict, err.Error()
	case errors.Is(err, store.ErrNotFound):
		return wire.CodeNotFound, err.Error()
	case errors.Is(err, policy.ErrDenied):
		return wire.CodeDenied, err.Error()
	case errors.Is(err, allowlist.ErrBlocked), errors.Is(err, allowlist.ErrNotAllowed):
		return wire.CodeBlocked, err.Error()
	case errors.Is(err, policy.ErrPinMismatch), errors.Is(err, policy.ErrNoPin):
		return wire.CodePolicy, err.Error()
	}
	return wire.CodeInternal, err.Error()
}

func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return fail(wire.CodeBadRequest, "thiếu tham số")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fail(wire.CodeBadRequest, "tham số sai: %v", err)
	}
	return nil
}

func (b *Broker) dispatch(ctx context.Context, req wire.Request, w *respWriter, peer string) error {
	switch req.Cmd {
	case wire.CmdStatus:
		return b.cmdStatus(w)
	case wire.CmdLock:
		b.Lock()
		w.ok(nil)
		return nil
	case wire.CmdSessionEnd:
		b.endSession(peer)
		w.ok(nil)
		return nil
	case wire.CmdSessionStart:
		return b.cmdSessionStart(ctx, w, peer)
	case wire.CmdGrants:
		w.ok(b.grantViews())
		return nil
	case wire.CmdGrantsRevoke:
		var a wire.GrantsRevokeArgs
		if err := decode(req.Args, &a); err != nil {
			return err
		}
		n, err := b.revokeGrants(a, peer)
		if err != nil {
			return err
		}
		w.ok(n)
		return nil
	}
	s, err := b.session(ctx)
	if err != nil {
		var ce *cmdErr
		if errors.As(err, &ce) || errors.Is(err, fsx.ErrLocked) {
			return err
		}
		return fail(wire.CodeLocked, "%v", err)
	}
	switch req.Cmd {
	case wire.CmdList:
		return b.cmdList(s, w)
	case wire.CmdGrant:
		var a wire.GrantArgs
		if err := decode(req.Args, &a); err != nil {
			return err
		}
		z, err := b.authorize(ctx, s, a.Secret, authReq{argv: a.Argv, agent: a.Agent}, peer)
		if err != nil {
			return err
		}
		w.ok(z.granted)
		return nil
	case wire.CmdRun, wire.CmdResolve:
		var a api.RunRequest
		if err := decode(req.Args, &a); err != nil {
			return err
		}
		return b.cmdRun(ctx, s, a, req.Cmd == wire.CmdResolve, w, peer)
	case wire.CmdReveal:
		var a wire.RevealArgs
		if err := decode(req.Args, &a); err != nil {
			return err
		}
		return b.cmdReveal(ctx, s, a.Name, w, peer)
	case wire.CmdSet:
		var a wire.SetArgs
		if err := decode(req.Args, &a); err != nil {
			return err
		}
		if err := b.cmdSet(ctx, s, a, peer); err != nil {
			return err
		}
		w.ok(nil)
		return nil
	case wire.CmdImport:
		var a wire.ImportArgs
		if err := decode(req.Args, &a); err != nil {
			return err
		}
		return b.cmdImport(ctx, s, a, w, peer)
	case wire.CmdSame:
		var a wire.SameArgs
		if err := decode(req.Args, &a); err != nil {
			return err
		}
		return b.cmdSame(ctx, s, a.Names, w, peer)
	case wire.CmdCopy:
		var a wire.CopyArgs
		if err := decode(req.Args, &a); err != nil {
			return err
		}
		return b.cmdCopy(ctx, s, a, w, peer)
	case wire.CmdFingerprint:
		w.ok(wire.FingerprintResult{Fingerprint: s.st.Fingerprint()})
		return nil
	case wire.CmdDelete:
		var a wire.DeleteArgs
		if err := decode(req.Args, &a); err != nil {
			return err
		}
		return b.cmdDelete(ctx, s, a.Names, w, peer)
	case wire.CmdPolicyApply:
		return b.cmdPolicyApply(ctx, s, w, peer)
	case wire.CmdConflicts:
		var out []wire.ConflictInfo
		for _, it := range s.st.Conflicts() {
			ci := wire.ConflictInfo{Name: it.Name, Item: it.Item}
			for _, h := range it.Heads {
				ci.Heads = append(ci.Heads, wire.ConflictHead{Hash: h.Hash, Dev: h.Dev, Seq: h.Seq, Op: h.Op})
			}
			out = append(out, ci)
		}
		w.ok(out)
		return nil
	case wire.CmdResolveConflict:
		var a wire.ResolveConflictArgs
		if err := decode(req.Args, &a); err != nil {
			return err
		}
		for _, it := range s.st.Conflicts() {
			if it.Name != a.Name {
				continue
			}
			cmd := "CHỌN bản giữ cho xung đột " + a.Name + ", giữ: " + a.Keep
			if _, err := b.humanApprove(ctx, s, approvalReq{op: "resolve-conflict", command: cmd, peer: peer, mode: policy.ApprovalUserPresence}); err != nil {
				if !isPending(err) {
					b.audBest(s, audit.Entry{Event: audit.EvDeny, Secret: a.Name, Approval: "resolve-conflict-refused", Peer: peer})
				}
				return refused(err, "resolve-conflict")
			}
			if _, err := s.st.ResolveConflict(it.Item, a.Keep); err != nil {
				return err
			}
			b.audBest(s, audit.Entry{Event: audit.EvSet, Secret: a.Name, Approval: "resolve-conflict", Peer: peer})
			w.ok(nil)
			return nil
		}
		return fail(wire.CodeNotFound, "không có xung đột cho %q", a.Name)
	case wire.CmdSync:
		var a wire.SyncArgs
		if len(req.Args) > 0 {
			if err := decode(req.Args, &a); err != nil {
				return err
			}
		}
		r, err := channel.Sync(ctx, s.st, a.Via, a.VerifyVia)
		if err != nil {
			return err
		}
		t := b.cfg.Now()
		b.mu.Lock()
		b.lastSync = &t
		b.mu.Unlock()
		w.ok(r)
		return nil
	}
	return fail(wire.CodeBadRequest, "lệnh lạ %q", req.Cmd)
}

// aud appends an audit entry; the error must be handled by callers that gate an action on it.
func (b *Broker) aud(s *session, e audit.Entry, peer string) error {
	e.Peer = peer
	err := s.led.Append(e)
	b.markDirty()
	return err
}

// audBest appends but only logs a failure (events that do not gate an action).
func (b *Broker) audBest(s *session, e audit.Entry) {
	if err := s.led.Append(e); err != nil {
		b.logf("ghi audit lỗi: %v", err)
	}
	b.markDirty()
}

func (b *Broker) cmdStatus(w *respWriter) error {
	now := b.cfg.Now()
	b.mu.Lock()
	s := b.sess
	st := api.Status{Unlocked: s != nil, Device: b.dev, Vault: b.vlt, LockAfter: lockAfter(b.cfg.IdleLock), LastSyncAt: b.lastSync, Grants: []api.GrantInfo{}}
	expiredDurable := false
	for k, g := range b.grants {
		if g.live(now) {
			st.Grants = append(st.Grants, g.GrantInfo)
		} else {
			expiredDurable = expiredDurable || g.Durable
			delete(b.grants, k)
		}
	}
	b.mu.Unlock()
	if expiredDurable {
		b.persistGrants()
	}
	sort.Slice(st.Grants, func(i, j int) bool { return st.Grants[i].Secret < st.Grants[j].Secret })
	if s != nil {
		st.Epoch = s.st.Epoch()
		st.Conflicts = len(s.st.Conflicts())
		_, err := b.loadPolicy(s)
		st.PolicyOK = err == nil
	}
	b.mu.Lock()
	full := wire.StatusFull{Status: st, Session: b.sessID != "", SessionID: b.sessID}

	if b.sessID != "" {
		t := b.sessStart
		full.SessionStart = &t
	}
	b.mu.Unlock()
	full.Pending = b.publishedCount()
	full.Approvers = len(b.approvers())
	w.ok(full)
	return nil
}

func (b *Broker) lastUsed(s *session) map[string]time.Time {
	out := map[string]time.Time{}
	es, err := s.led.ShowVerified(time.Time{})
	if err != nil {
		return out
	}
	for _, e := range es {
		if e.Event != audit.EvRun {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, e.Time); err == nil && t.After(out[e.Secret]) {
			out[e.Secret] = t
		}
	}
	return out
}

func (b *Broker) cmdList(s *session, w *respWriter) error {
	used := b.lastUsed(s)
	out := []api.SecretInfo{}
	for _, it := range s.st.List() {
		if it.Deleted || it.Name == "" {
			continue
		}
		si := api.SecretInfo{Name: it.Name, Env: it.Env, Kind: it.Kind, Conflict: it.Conflict}
		if t, ok := used[it.Name]; ok {
			t := t
			si.LastUsed = &t
		}
		out = append(out, si)
	}
	w.ok(out)
	return nil
}

// authReq is what the caller asks for.
type authReq struct {
	argv    []string
	dir     string
	agent   string
	as      string
	resolve bool
}

type authz struct {
	info    store.ItemInfo
	g       *policy.Grant
	pv      *policyView
	match   *allowlist.Match
	kind    string // effective kind: env|file|oracle-wallet
	granted api.GrantInfo
}

func redactArgv(argv []string, r *redact.Redactor) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = r.String(a)
	}
	return out
}

// effectiveKind applies M1: policy kind (else item kind) decides; `--as` never changes a wallet,
// and only switches other kinds to a kind in allow_as; `resolve` needs kind template.
func effectiveKind(g *policy.Grant, itemKind, as string, resolve bool) (string, error) {
	base := g.Kind
	if base == "" {
		base = itemKind
	}
	if base == "" {
		base = "env"
	}
	if resolve && base != "template" {
		return "", fail(wire.CodeBlocked, "resolve chỉ dùng với secret có kind template (policy/item đang là %s)", base)
	}
	cur := base
	if base == "template" {
		cur = "env"
	}
	if as == "" {
		return cur, nil
	}
	if base == "oracle-wallet" {
		return "", fail(wire.CodeBlocked, "--as không được đổi kind của secret oracle-wallet")
	}
	want := as
	if as == "wallet" {
		want = "oracle-wallet"
	}
	if want == cur {
		return cur, nil
	}
	for _, a := range g.AllowAs {
		if a == as {
			return want, nil
		}
	}
	return "", fail(wire.CodeBlocked, "policy không cho --as %s với secret này (allow_as)", as)
}

// authorizeCheck applies policy, allowlist and kind rules for one secret WITHOUT prompting.
// pending is true when a (new) grant still needs approval.
func (b *Broker) authorizeCheck(s *session, name string, rq authReq, peer string) (z *authz, pending bool, err error) {
	deny := func(reason, env string, err error) (*authz, bool, error) {
		b.audBest(s, audit.Entry{Event: audit.EvDeny, Secret: name, Env: env, Argv: rq.argv, Agent: rq.agent, Peer: peer, Approval: reason})
		return nil, false, err
	}
	if len(rq.argv) == 0 {
		return nil, false, fail(wire.CodeBadRequest, "thiếu lệnh")
	}
	info, err := s.st.FindByName(name)
	if err != nil {
		return nil, false, err
	}
	if info.Conflict {
		return deny("conflict", info.Env, fmt.Errorf("%w: %q có xung đột, chạy `kg conflicts`", store.ErrConflict, name))
	}
	pv, err := b.loadPolicy(s)
	if err != nil {
		return deny("pin", info.Env, err)
	}
	g, err := pv.L.Policy.Lookup(name, info.Env)
	if err != nil {
		return deny("policy", info.Env, err)
	}
	match, err := allowlist.Check(pv.res[g.Pattern], rq.argv, rq.dir)
	if err != nil {
		return deny("allowlist", info.Env, err)
	}
	kind, err := effectiveKind(g, info.Kind, rq.as, rq.resolve)
	if err != nil {
		return deny("kind", info.Env, err)
	}
	key := grantKey{name, match.Entry.Raw, match.Path}
	now := b.cfg.Now()
	b.mu.Lock()
	cur, ok := b.grants[key]
	b.mu.Unlock()
	z = &authz{info: info, g: g, pv: pv, match: match, kind: kind}
	// A durable grant only counts while the policy still asks for the approval mode it was given under.
	if ok && cur.live(now) && (!cur.Durable || cur.Approval == g.Approval) {
		z.granted = cur.GrantInfo
		return z, false, nil
	}
	return z, true, nil
}

// grantNow records (and audits) the grant for z; approval has already happened if it was needed.
// by says who approved ("hello", "paste:<dev>", "remote:<dev>"); a session or `approval: none` grant
// is volatile, anything else follows an explicit human approval and is remembered on disk.
func (b *Broker) grantNow(s *session, z *authz, rq authReq, peer, sessID, by string) error {
	key := grantKey{z.info.Name, z.match.Entry.Raw, z.match.Path}
	appr, sid := z.g.Approval, ""
	if sessID != "" && appr != policy.ApprovalNone {
		appr, sid = "session", sessID
		by = "session"
	}
	now := b.cfg.Now()
	if appr == policy.ApprovalNone {
		by = "none"
	}
	ge := grantEntry{GrantInfo: api.GrantInfo{Secret: z.info.Name, Pattern: z.match.Entry.Raw, Approval: appr},
		Path: z.match.Path, By: by, At: now, Durable: sessID == "" && z.g.Approval != policy.ApprovalNone}
	if z.g.TTL > 0 {
		ge.Expires = now.Add(z.g.TTL)
	}
	gi := ge.GrantInfo
	auditAppr := appr
	if sid == "" && apprName(by) != policy.ApprovalUserPresence {
		auditAppr = by // remote:<dev> / paste:<dev>
	}
	if err := b.aud(s, audit.Entry{Event: audit.EvGrant, Secret: z.info.Name, Env: z.info.Env, Argv: rq.argv, Agent: rq.agent, Approval: auditAppr, Session: sid}, peer); err != nil {
		return fmt.Errorf("không ghi được audit, không cấp grant: %w", err)
	}
	b.mu.Lock()
	b.grants[key] = ge
	b.mu.Unlock()
	if ge.Durable {
		b.persistGrants()
	}
	z.granted = gi
	return nil
}

// authorize is authorizeMany for one secret.
func (b *Broker) authorize(ctx context.Context, s *session, name string, rq authReq, peer string) (*authz, error) {
	zs, err := b.authorizeMany(ctx, s, []string{name}, rq, peer)
	if err != nil {
		return nil, err
	}
	return zs[0], nil
}

// authorizeMany checks every secret first (all must pass), then asks ONE approval per approval mode
// listing every secret that still lacks a grant, then caches each grant with its own TTL.
func (b *Broker) authorizeMany(ctx context.Context, s *session, names []string, rq authReq, peer string) ([]*authz, error) {
	zs := make([]*authz, len(names))
	var pend []int
	for i, n := range names {
		z, pending, err := b.authorizeCheck(s, n, rq, peer)
		if err != nil {
			return nil, err
		}
		zs[i] = z
		if i > 0 && z.match.Path != zs[0].match.Path {
			return nil, fail(wire.CodeBlocked, "các secret khớp chương trình khác nhau")
		}
		if pending {
			pend = append(pend, i)
		}
	}
	byMode := map[string][]int{}
	var modes []string
	for _, i := range pend {
		m := zs[i].g.Approval
		if m == policy.ApprovalNone {
			continue
		}
		if _, ok := byMode[m]; !ok {
			modes = append(modes, m)
		}
		byMode[m] = append(byMode[m], i)
	}
	sessID := ""
	b.mu.Lock()
	sessID = b.sessID
	b.mu.Unlock()
	byMode2 := map[string]string{}
	for _, m := range modes {
		if sessID != "" {
			continue // work session: user-presence/device grants are given without a prompt
		}
		idx := byMode[m]
		var secretList []string
		for _, i := range idx {
			secretList = append(secretList, names[i])
		}
		z0 := zs[idx[0]]
		cmd := approve.FormatArgv(append([]string{z0.match.Path}, rq.argv[1:]...))
		prod := false
		for _, i := range idx {
			prod = prod || policy.IsProd(names[i], zs[i].info.Env)
		}
		res, err := b.humanApprove(ctx, s, approvalReq{op: "grant", secrets: secretList, command: cmd, agent: rq.agent, peer: peer,
			prod: prod, mode: m, session: true})
		byMode2[m] = res.by
		if err != nil {
			if isPending(err) {
				return nil, err
			}
			for _, i := range idx {
				b.audBest(s, audit.Entry{Event: audit.EvDeny, Secret: names[i], Env: zs[i].info.Env, Argv: rq.argv, Agent: rq.agent, Peer: peer, Approval: "approval-failed"})
			}
			return nil, fmt.Errorf("%w: %v", policy.ErrDenied, err)
		}
		if res.choice == "session" {
			sessID = b.openSession(s, res.by) // the phone chose "allow and open a work session"
		}
	}
	for _, i := range pend {
		if err := b.grantNow(s, zs[i], rq, peer, sessID, byMode2[zs[i].g.Approval]); err != nil {
			return nil, err
		}
	}
	return zs, nil
}

const maxTemplate = 1 << 20

func (b *Broker) cmdRun(ctx context.Context, s *session, req api.RunRequest, isResolve bool, w *respWriter, peer string) error {
	if len(req.Argv) == 0 {
		return fail(wire.CodeBadRequest, "thiếu lệnh sau --")
	}
	names := append([]string(nil), req.Secrets...)
	var tmpl []byte
	if isResolve {
		if req.Resolve == "" {
			return fail(wire.CodeBadRequest, "thiếu file template")
		}
		st, err := os.Stat(req.Resolve)
		if err != nil {
			return fail(wire.CodeBadRequest, "đọc template: %v", err)
		}
		if st.Size() > maxTemplate {
			return fail(wire.CodeBadRequest, "template quá lớn")
		}
		if tmpl, err = os.ReadFile(req.Resolve); err != nil {
			return fail(wire.CodeBadRequest, "đọc template: %v", err)
		}
		names = append(names, execwrap.TemplateNames(string(tmpl))...)
	}
	seen := map[string]bool{}
	var uniq []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			uniq = append(uniq, n)
		}
	}
	if len(uniq) == 0 {
		return fail(wire.CodeBadRequest, "cần ít nhất một --secret")
	}
	into := req.Into
	if isResolve {
		if into == "" {
			into = "KG_RESOLVED"
		}
		if err := envname.Check(into); err != nil {
			return fail(wire.CodeBadRequest, "%v", err)
		}
	}
	var zs []*authz
	var secrets []execwrap.Secret
	var rs []redact.Secret
	values := map[string]string{}
	var maxRun time.Duration
	azs, err := b.authorizeMany(ctx, s, uniq, authReq{argv: req.Argv, dir: req.Dir, agent: req.Agent, as: req.As, resolve: isResolve}, peer)
	if err != nil {
		return err
	}
	for i, n := range uniq {
		z := azs[i]
		p, _, err := s.st.Get(z.info.Item)
		if err != nil {
			return err
		}
		zs = append(zs, z)
		envN, tns := p.EnvName, p.TNS
		if z.g.EnvName != "" {
			envN = z.g.EnvName
		}
		if z.g.TNSAlias != "" {
			tns = z.g.TNSAlias
		}
		secrets = append(secrets, execwrap.Secret{Name: n, Value: p.Value, Kind: z.kind, EnvName: envN, TNSAlias: tns, User: p.User, FileExt: p.FileExt})
		rs = append(rs, redact.Secret{Name: n, Value: p.Value})
		values[n] = p.Value
		if z.g.MaxRuntime > 0 && (maxRun == 0 || z.g.MaxRuntime < maxRun) {
			maxRun = z.g.MaxRuntime
		}
	}
	b.touch() // authorized run = real use
	red := redact.New(rs)
	if isResolve {
		// Template secrets are only substituted into the temp file; they are not also injected as env vars.
		secrets = nil
	}
	orc := zs[0].pv.L.Policy.Oracle
	cfg := execwrap.Config{Java: orc.Java, PkiJar: orc.PkiJar, TNSAdmin: orc.TNSAdmin, RunDir: RunDir(b.cfg.Home)}

	// Audit "run-start" BEFORE anything executes; a failed append means no run.
	argvA := redactArgv(req.Argv, red)
	for _, z := range zs {
		e := audit.Entry{Event: audit.EvRunStart, Secret: z.info.Name, Env: z.info.Env, Argv: argvA, Agent: req.Agent, Approval: z.granted.Approval}
		if err := b.aud(s, e, peer); err != nil {
			return fmt.Errorf("không ghi được audit bắt đầu, không chạy lệnh: %w", err)
		}
	}

	env, err := execwrap.NewEnv(ctx, cfg, secrets, "")
	if err != nil {
		return fmt.Errorf("%s", red.String(err.Error()))
	}
	defer env.Cleanup()
	if isResolve {
		out, err := execwrap.ResolveTemplate(string(tmpl), values)
		if err != nil {
			return err
		}
		if _, err := env.AddFile(cfg, into, []byte(out), strings.TrimPrefix(filepath.Ext(req.Resolve), ".")); err != nil {
			return err
		}
	}
	// One ordered redaction stream for stdout+stderr: a value split across the two cannot slip through.
	so := red.NewWriter(streamWriter{w, "stdout"})
	code, runErr := env.Run(ctx, execwrap.RunOpts{Argv: zs[0].match.Argv, Dir: req.Dir, Stdout: so, Stderr: so, MaxRuntime: maxRun})
	so.Flush()
	for _, z := range zs {
		e := audit.Entry{Event: audit.EvRun, Secret: z.info.Name, Env: z.info.Env, Argv: argvA, Agent: req.Agent, Approval: z.granted.Approval}
		c := code
		e.Exit = &c
		b.aud(s, e, peer)
	}
	if runErr != nil {
		return fmt.Errorf("%s", red.String(runErr.Error()))
	}
	w.frame(wire.Frame{T: wire.FrameExit, Exit: code})
	return nil
}

func (b *Broker) cmdReveal(ctx context.Context, s *session, name string, w *respWriter, peer string) error {
	b.mu.Lock()
	blocked := b.cfg.Now().Before(b.revealBlock)
	b.mu.Unlock()
	if blocked {
		return fail(wire.CodeDenied, "reveal tạm khóa sau lần từ chối trước (chờ tối đa %s)", b.cfg.RevealCooldown)
	}
	info, err := s.st.FindByName(name)
	if err != nil {
		return err
	}
	if info.Conflict {
		return fmt.Errorf("%w: %q", store.ErrConflict, name)
	}
	res, err := b.humanApprove(ctx, s, approvalReq{op: "reveal", secrets: []string{name}, localOnly: true, peer: peer,
		command: "HIỂN THỊ giá trị trên cửa sổ broker (kg reveal)", mode: policy.ApprovalUserPresence})
	if err != nil {
		b.mu.Lock()
		b.revealBlock = b.cfg.Now().Add(b.cfg.RevealCooldown)
		b.mu.Unlock()
		b.audBest(s, audit.Entry{Event: audit.EvDeny, Secret: name, Env: info.Env, Approval: "reveal-refused", Peer: peer})
		return refused(err, "reveal")
	}
	p, _, err := s.st.Get(info.Item)
	if err != nil {
		return err
	}
	if err := b.aud(s, audit.Entry{Event: audit.EvReveal, Secret: name, Env: info.Env, Approval: apprName(res.by)}, peer); err != nil {
		return fmt.Errorf("không ghi được audit, không hiển thị: %w", err)
	}
	// The value is shown on the broker's own terminal/dialog, never returned over the socket.
	if err := b.cfg.Prompt.ShowSecret(ctx, approve.Sanitize(name, approve.MaxPrompt), p.Value); err != nil {
		return fail(wire.CodeDenied, "không hiển thị được giá trị: %v", err)
	}
	w.ok(nil)
	return nil
}

var validKinds = map[string]bool{"env": true, "file": true, "oracle-wallet": true, "template": true}

const maxNameLen = 200

// validateSet normalizes and validates set metadata (no value involved).
func (b *Broker) validateSet(r *api.SetRequest) error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || len(r.Name) > maxNameLen || strings.ContainsAny(r.Name, "\r\n\x00\x1b") {
		return fail(wire.CodeBadRequest, "tên secret không hợp lệ")
	}
	if r.Kind == "" {
		r.Kind = "env"
	}
	if !validKinds[r.Kind] {
		return fail(wire.CodeBadRequest, "kind %q không hợp lệ", r.Kind)
	}
	if r.Kind == "oracle-wallet" && (r.User == "" || r.TNSAlias == "") {
		return fail(wire.CodeBadRequest, "oracle-wallet cần --user và --tns-alias")
	}
	if r.EnvName != "" {
		if err := envname.Check(r.EnvName); err != nil {
			return fail(wire.CodeBadRequest, "%v", err)
		}
	}
	r.Env = strings.ToLower(strings.TrimSpace(r.Env))
	if r.Env == "" {
		r.Env = "dev"
	}
	if policy.IsProd(r.Name, "") && !policy.IsProd("", r.Env) {
		fmt.Fprintf(b.out(), "[broker] CẢNH BÁO: tên %q trông như PROD nhưng env=%s; policy vẫn coi là PROD theo tên.\n", approve.Sanitize(r.Name, 100), r.Env)
	}
	return nil
}

// storeSecret writes the item (value already obtained) and audits it.
func (b *Broker) storeSecret(s *session, r api.SetRequest, value, event, source, peer string) error {
	item := ""
	if cur, err := s.st.FindByName(r.Name); err == nil {
		if cur.Conflict {
			return fmt.Errorf("%w: %q", store.ErrConflict, r.Name)
		}
		item = cur.Item
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	_, err := s.st.Put(item, record.Plain{Name: r.Name, Value: value, Desc: r.Desc, Tags: r.Tags, Env: r.Env, Kind: r.Kind,
		EnvName: r.EnvName, TNS: r.TNSAlias, User: r.User, FileExt: r.FileExt})
	if err != nil {
		return err
	}
	e := audit.Entry{Event: event, Secret: r.Name, Env: r.Env, Peer: peer}
	if source != "" {
		e.Agent = "import:" + source
	}
	b.audBest(s, e)
	return nil
}

func (b *Broker) exists(s *session, name string) bool {
	_, err := s.st.FindByName(name)
	return err == nil
}

// cmdSet: metadata arrives over the socket; the value is typed (hidden) on the broker's terminal,
// which is also the human-presence check. Overwriting needs an extra user-presence approval.
func (b *Broker) cmdSet(ctx context.Context, s *session, a wire.SetArgs, peer string) error {
	r := a.Request
	if r.Value != "" {
		return fail(wire.CodeBadRequest, "giá trị secret không được gửi qua socket")
	}
	if err := b.validateSet(&r); err != nil {
		return err
	}
	var value string
	var fileBind string
	if a.FromFile != "" {
		// Read first: the approval is bound to exactly these bytes, which are also the ones stored.
		raw, err := os.ReadFile(a.FromFile)
		if err != nil {
			return fail(wire.CodeBadRequest, "đọc file: %v", err)
		}
		value = string(raw)
		sum := sha256.Sum256(raw)
		fileBind = "sha256:" + hex.EncodeToString(sum[:])
	}
	if b.exists(s, r.Name) {
		if _, err := b.humanApprove(ctx, s, approvalReq{op: "overwrite", secrets: []string{r.Name}, localOnly: true, peer: peer,
			command: "GHI ĐÈ secret đã có", mode: policy.ApprovalUserPresence, prod: policy.IsProd(r.Name, r.Env)}); err != nil {
			return refused(err, "ghi đè")
		}
	}
	if a.FromFile != "" {
		if _, err := b.humanApprove(ctx, s, approvalReq{op: "set-file", secrets: []string{r.Name}, bind: fileBind, peer: peer,
			command: "ĐỌC giá trị từ file " + a.FromFile, mode: policy.ApprovalUserPresence, prod: policy.IsProd(r.Name, r.Env)}); err != nil {
			return refused(err, "đọc file")
		}
	} else {
		v, err := b.cfg.Prompt.ReadSecret(ctx, fmt.Sprintf("[broker] Nhập giá trị cho %q (ẩn; yêu cầu từ %s): ", approve.Sanitize(r.Name, 100), approve.Sanitize(peer, 200)))
		if err != nil {
			return fail(wire.CodeDenied, "không nhập được giá trị: %v", err)
		}
		value = v
		b.touch()
	}
	if value == "" {
		return fail(wire.CodeBadRequest, "giá trị rỗng")
	}
	return b.storeSecret(s, r, value, audit.EvSet, "", peer)
}

type importItem struct {
	req   api.SetRequest
	value string
}

// bindItems is "sha256:<hex>" over lp(name)+lp(value) of every parsed item: exactly the data that
// will be written or compared, so a decision made for other file contents never applies.
func bindItems(items []importItem) string {
	h := sha256.New()
	lp := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	for _, it := range items {
		lp(it.req.Name)
		lp(it.value)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func itemsProd(items []importItem) bool {
	for _, it := range items {
		if policy.IsProd(it.req.Name, it.req.Env) {
			return true
		}
	}
	return false
}

func (b *Broker) cmdImport(ctx context.Context, s *session, a wire.ImportArgs, w *respWriter, peer string) error {
	if (a.Dotenv == "") == (a.Gitleaks == "") {
		return fail(wire.CodeBadRequest, "chọn đúng một nguồn: dotenv hoặc gitleaks")
	}
	env := strings.ToLower(strings.TrimSpace(a.Env))
	if env == "" {
		env = "dev"
	}
	var items []importItem
	var apply func() error
	src := a.Dotenv
	if a.Dotenv != "" {
		ents, err := importer.ParseDotenv(a.Dotenv)
		if err != nil {
			return fail(wire.CodeBadRequest, "%v", err)
		}
		refs := map[string]string{}
		for _, e := range ents {
			n := importer.SuggestName(a.Prefix, e.Key)
			refs[e.Key] = n
			r := api.SetRequest{Name: n, Kind: "env", Env: env, EnvName: e.Key}
			if envname.Check(e.Key) != nil {
				r.EnvName = "" // loader-style names fall back to KG_<NAME>
			}
			items = append(items, importItem{r, e.Value})
		}
		apply = func() error { return importer.RewriteDotenv(a.Dotenv, refs) }
	} else {
		src = a.Gitleaks
		fds, err := importer.ParseGitleaks(a.Gitleaks)
		if err != nil {
			return fail(wire.CodeBadRequest, "%v", err)
		}
		used := map[string]int{}
		var refs []string
		for _, f := range fds {
			base := importer.SuggestName(a.Prefix, f.RuleID)
			n := base
			if used[base]++; used[base] > 1 {
				n = fmt.Sprintf("%s-%d", base, used[base])
			}
			refs = append(refs, n)
			en := strings.ToUpper(strings.NewReplacer("/", "_", "-", "_").Replace(strings.TrimPrefix(n, a.Prefix)))
			r := api.SetRequest{Name: n, Kind: "env", Env: env, EnvName: en}
			if envname.Check(en) != nil {
				r.EnvName = ""
			}
			items = append(items, importItem{r, f.Secret})
		}
		apply = func() error {
			for i, f := range fds {
				if err := importer.RewriteFinding(f, refs[i]); err != nil {
					return err
				}
			}
			return nil
		}
	}
	if a.Compare {
		if a.Dotenv == "" {
			return fail(wire.CodeBadRequest, "--compare chỉ hỗ trợ --dotenv")
		}
		return b.compareDotenv(ctx, s, a, items, w, peer)
	}
	if len(items) == 0 {
		w.ok(wire.ImportResult{})
		return nil
	}
	overwrites := 0
	for i := range items {
		if err := b.validateSet(&items[i].req); err != nil {
			return err
		}
		if b.exists(s, items[i].req.Name) {
			overwrites++
		}
	}
	cmd := fmt.Sprintf("NHẬP %d secret từ file %s (ghi đè %d tên đã có; ghi lại file nguồn: %v)", len(items), src, overwrites, a.Rewrite)
	if _, err := b.humanApprove(ctx, s, approvalReq{op: "import", command: cmd, bind: bindItems(items), peer: peer, prod: itemsProd(items),
		mode: policy.ApprovalUserPresence}); err != nil {
		if !isPending(err) {
			b.audBest(s, audit.Entry{Event: audit.EvDeny, Approval: "import-refused", Peer: peer})
		}
		return refused(err, "import")
	}
	base := filepath.Base(src)
	var names []string
	for _, it := range items {
		if err := b.storeSecret(s, it.req, it.value, audit.EvImport, base, peer); err != nil {
			return fmt.Errorf("%s: %w", it.req.Name, err)
		}
		names = append(names, it.req.Name)
	}
	if a.Rewrite {
		if err := apply(); err != nil {
			return fmt.Errorf("đã nhập nhưng chưa sửa được file nguồn: %w", err)
		}
	}
	w.ok(wire.ImportResult{Count: len(names), Names: names})
	return nil
}

func (b *Broker) cmdPolicyApply(ctx context.Context, s *session, w *respWriter, peer string) error {
	polPath := filepath.Join(b.cfg.Home, "policy.yaml")
	pinPath := filepath.Join(b.cfg.Home, "state", "policy.pin")
	keptPath := filepath.Join(b.cfg.Home, "state", "policy.pinned.yaml")
	mac := s.st.LocalMacKey()
	data, err := os.ReadFile(polPath)
	if err != nil {
		return fail(wire.CodeBadRequest, "đọc policy.yaml: %v", err)
	}
	p, err := policy.Parse(data)
	if err != nil {
		return fail(wire.CodeBadRequest, "%v", err)
	}
	// Diff base: the last applied policy, only trusted if it still hashes to the MAC'd pin.
	var base *policy.Policy
	var oldVer uint64
	if h, v, err := policy.ReadPin(pinPath, mac); err == nil {
		oldVer = v
		if kept, err := os.ReadFile(keptPath); err == nil && policy.Hash(kept) == h {
			base, _ = policy.Parse(kept)
		}
	}
	h := policy.Hash(data)
	diff := policy.Diff(base, p)
	warns := policy.Warnings(p)
	var detail strings.Builder
	if base == nil {
		detail.WriteString("(không có bản đã ghim đáng tin để so, liệt kê toàn bộ)\n")
	}
	if len(diff) == 0 {
		detail.WriteString("không có thay đổi grant/oracle\n")
	}
	for _, d := range diff {
		detail.WriteString(approve.Sanitize(d, 2000) + "\n")
	}
	if len(warns) > 0 {
		detail.WriteString("\n")
		for _, wn := range warns {
			detail.WriteString(approve.Sanitize(wn, 1000) + "\n")
		}
	}
	cmd := fmt.Sprintf("ÁP DỤNG policy.yaml v%d: %d thay đổi, %d cảnh báo (xem diff kèm theo)", oldVer+1, len(diff), len(warns))
	res, err := b.humanApprove(ctx, s, approvalReq{op: "policy", command: cmd, detail: detail.String(), bind: h, peer: peer, mode: policy.ApprovalUserPresence})
	if err != nil {
		if !isPending(err) {
			b.audBest(s, audit.Entry{Event: audit.EvDeny, Approval: "policy-refused", Peer: peer})
		}
		return refused(err, "policy apply")
	}
	if err := policy.WritePin(pinPath, data, mac, oldVer+1); err != nil {
		return err
	}
	if err := fsx.WriteAtomic(keptPath, data); err != nil {
		return err
	}
	b.mu.Lock()
	b.dropVolatileGrants() // session / approval:none grants lapse
	b.pcache = nil         // resolve programs again with the new policy
	b.polMax = oldVer + 1
	b.mu.Unlock()
	keep := map[string]bool{}
	for _, g := range p.Grants {
		for _, c := range g.AllowCommands {
			keep[c] = true
		}
	}
	b.dropGrantsNotIn(keep) // durable grants of an allow_commands entry the new policy no longer has
	if _, err := b.loadPolicy(s); err == nil {
		b.logf("policy v%d áp dụng; đã xóa grant tạm và grant của mục allow_commands không còn", oldVer+1)
	}
	b.audBest(s, audit.Entry{Event: audit.EvPolicy, Argv: []string{h, fmt.Sprintf("v%d", oldVer+1)}, Approval: apprName(res.by), Peer: peer})
	w.ok(wire.PolicyResult{Hash: h, Grants: len(p.Grants)})
	return nil
}

// cmdDelete tombstones every named secret after ONE user-presence approval. Unknown names fail
// before anything is written.
func (b *Broker) cmdDelete(ctx context.Context, s *session, names []string, w *respWriter, peer string) error {
	if len(names) == 0 {
		return fail(wire.CodeBadRequest, "thiếu tên secret")
	}
	seen := map[string]bool{}
	var infos []store.ItemInfo
	for _, raw := range names {
		n := strings.TrimSpace(raw) // names pasted from CRLF files/pipes often carry a stray \r
		if seen[n] {
			continue
		}
		seen[n] = true
		it, err := s.st.FindByName(n)
		if err != nil {
			q := strconv.Quote(raw) // escapes control characters, so a hidden \r is visible in the error
			if len(q) > 120 {
				q = q[:120] + `…"`
			}
			return fmt.Errorf("%s: %w", q, err)
		}
		infos = append(infos, it)
	}
	var qs []string
	for _, it := range infos {
		qs = append(qs, strconv.Quote(approve.Sanitize(it.Name, 100)))
	}
	cmd := fmt.Sprintf("XÓA %d secret: %s", len(infos), strings.Join(qs, ", "))
	prod := false
	for _, it := range infos {
		prod = prod || policy.IsProd(it.Name, it.Env)
	}
	res, err := b.humanApprove(ctx, s, approvalReq{op: "delete", command: cmd, peer: peer, prod: prod, mode: policy.ApprovalUserPresence})
	if err != nil {
		if !isPending(err) {
			b.audBest(s, audit.Entry{Event: audit.EvDeny, Approval: "delete-refused", Peer: peer})
		}
		return refused(err, "xóa")
	}
	var done []string
	for _, it := range infos {
		if _, err := s.st.Delete(it.Item); err != nil {
			return fmt.Errorf("đã xóa %v, lỗi ở %q: %w", done, it.Name, err)
		}
		done = append(done, it.Name)
		if err := b.aud(s, audit.Entry{Event: audit.EvDelete, Secret: it.Name, Env: it.Env, Approval: apprName(res.by)}, peer); err != nil {
			b.logf("ghi audit lỗi: %v", err)
		}
	}
	w.ok(wire.DeleteResult{Names: done})
	return nil
}

// compareDotenv reports same|diff|missing per key, extra vault names under the prefix, and unparsed
// lines. It reads a plaintext file and decrypts, so it needs user-presence. No value leaves.
func (b *Broker) compareDotenv(ctx context.Context, s *session, a wire.ImportArgs, items []importItem, w *respWriter, peer string) error {
	cmd := fmt.Sprintf("SO SÁNH %d khóa của file %s với vault (chỉ trả trạng thái)", len(items), a.Dotenv)
	ar, err := b.humanApprove(ctx, s, approvalReq{op: "compare", command: cmd, bind: bindItems(items), peer: peer, prod: itemsProd(items), mode: policy.ApprovalUserPresence})
	if err != nil {
		if !isPending(err) {
			b.audBest(s, audit.Entry{Event: audit.EvDeny, Approval: "compare-refused", Peer: peer})
		}
		return refused(err, "so sánh")
	}
	var res wire.CompareResult
	inFile := map[string]bool{}
	for _, it := range items {
		inFile[it.req.Name] = true
		st := "missing"
		if info, err := s.st.FindByName(it.req.Name); err == nil && !info.Conflict {
			if p, _, err := s.st.Get(info.Item); err == nil {
				st = "diff"
				if p.Value == it.value {
					st = "same"
				}
			}
		}
		res.Items = append(res.Items, wire.CompareItem{Name: it.req.Name, Status: st})
	}
	for _, info := range s.st.List() {
		if info.Deleted || info.Name == "" || !strings.HasPrefix(info.Name, a.Prefix) || inFile[info.Name] {
			continue
		}
		res.Extra = append(res.Extra, info.Name)
	}
	sort.Strings(res.Extra)
	res.Unparsed, _ = importer.DotenvAnomalies(a.Dotenv)
	b.audBest(s, audit.Entry{Event: audit.EvCompare, Agent: "import:" + filepath.Base(a.Dotenv), Peer: peer, Approval: apprName(ar.by)})
	w.ok(res)
	return nil
}

// cmdSessionStart opens a work session. If the vault is locked the unlock approval doubles as the
// session approval (one prompt); otherwise one user-presence prompt is shown.
func (b *Broker) cmdSessionStart(ctx context.Context, w *respWriter, peer string) error {
	if err := b.StartSession(ctx, peer); err != nil {
		return err
	}
	w.ok(nil)
	return nil
}

func quoteNames(names []string) string {
	qs := make([]string, len(names))
	for i, n := range names {
		qs[i] = strconv.Quote(approve.Sanitize(n, 100))
	}
	return strings.Join(qs, ", ")
}

// cmdSame compares decrypted values (constant time) with the first name. Always user-presence,
// even inside a work session. Only verdicts leave the broker.
func (b *Broker) cmdSame(ctx context.Context, s *session, names []string, w *respWriter, peer string) error {
	if len(names) < 2 {
		return fail(wire.CodeBadRequest, "cần ít nhất hai tên")
	}
	vals := make([]string, len(names))
	for i, n := range names {
		n = strings.TrimSpace(n)
		names[i] = n
		it, err := s.st.FindByName(n)
		if err != nil {
			return fmt.Errorf("%s: %w", strconv.Quote(n), err)
		}
		if it.Conflict {
			return fmt.Errorf("%w: %q", store.ErrConflict, n)
		}
		p, _, err := s.st.Get(it.Item)
		if err != nil {
			return err
		}
		vals[i] = p.Value
	}
	cmd := "SO SÁNH giá trị (chỉ trả same/diff): " + quoteNames(names)
	if _, err := b.humanApprove(ctx, s, approvalReq{op: "same", command: cmd, peer: peer, localOnly: true, mode: policy.ApprovalUserPresence}); err != nil {
		if !isPending(err) {
			b.audBest(s, audit.Entry{Event: audit.EvDeny, Approval: "same-refused", Peer: peer})
		}
		return refused(err, "so sánh")
	}
	var res wire.SameResult
	for i := 1; i < len(names); i++ {
		st := "diff"
		if subtle.ConstantTimeCompare([]byte(vals[0]), []byte(vals[i])) == 1 {
			st = "same"
		}
		res.Items = append(res.Items, wire.SameItem{Name: names[i], Status: st})
	}
	b.audBest(s, audit.Entry{Event: audit.EvSame, Secret: names[0], Argv: names[1:], Peer: peer, Approval: policy.ApprovalUserPresence})
	w.ok(res)
	return nil
}

// cmdCopy creates each dst from its src (value, kind, env, tns, user, file_ext, desc, tags), never
// overwriting. All pairs are validated first; one user-presence approval covers the batch, even
// inside a work session.
func (b *Broker) cmdCopy(ctx context.Context, s *session, a wire.CopyArgs, w *respWriter, peer string) error {
	if len(a.Pairs) == 0 {
		return fail(wire.CodeBadRequest, "thiếu cặp nguồn/đích")
	}
	type job struct {
		req   api.SetRequest
		value string
		src   string
	}
	var jobs []job
	dsts := map[string]bool{}
	for _, pr := range a.Pairs {
		src := strings.TrimSpace(pr.Src)
		it, err := s.st.FindByName(src)
		if err != nil {
			return fmt.Errorf("%s: %w", strconv.Quote(pr.Src), err)
		}
		if it.Conflict {
			return fmt.Errorf("%w: %q", store.ErrConflict, src)
		}
		p, _, err := s.st.Get(it.Item)
		if err != nil {
			return err
		}
		r := api.SetRequest{Name: pr.Dst, Kind: p.Kind, Env: p.Env, Desc: p.Desc, Tags: p.Tags,
			EnvName: p.EnvName, TNSAlias: p.TNS, User: p.User, FileExt: p.FileExt}
		if a.EnvName != "" {
			r.EnvName = a.EnvName
		}
		if err := b.validateSet(&r); err != nil {
			return err
		}
		if b.exists(s, r.Name) || dsts[r.Name] {
			return fail(wire.CodeBadRequest, "đích %q đã tồn tại (kg cp không ghi đè)", approve.Sanitize(r.Name, 100))
		}
		dsts[r.Name] = true
		jobs = append(jobs, job{r, p.Value, src})
	}
	var desc []string
	for _, j := range jobs {
		desc = append(desc, strconv.Quote(approve.Sanitize(j.src, 100))+" -> "+strconv.Quote(approve.Sanitize(j.req.Name, 100)))
	}
	cmd := fmt.Sprintf("SAO CHÉP %d secret: %s", len(jobs), strings.Join(desc, ", "))
	if _, err := b.humanApprove(ctx, s, approvalReq{op: "copy", command: cmd, peer: peer, localOnly: true, mode: policy.ApprovalUserPresence}); err != nil {
		if !isPending(err) {
			b.audBest(s, audit.Entry{Event: audit.EvDeny, Approval: "copy-refused", Peer: peer})
		}
		return refused(err, "sao chép")
	}
	var done []string
	for _, j := range jobs {
		if err := b.storeSecret(s, j.req, j.value, audit.EvCopy, "", peer); err != nil {
			return fmt.Errorf("đã tạo %v, lỗi ở %q: %w", done, j.req.Name, err)
		}
		done = append(done, j.req.Name)
	}
	w.ok(wire.CopyResult{Names: done})
	return nil
}
