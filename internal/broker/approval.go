package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"keygate/internal/approve"
	"keygate/internal/broker/wire"
	"keygate/internal/policy"
	"keygate/internal/remote"
)

// maxDetail is the largest detail text a phone may be asked to approve: it is shown in full or not at all.
const maxDetail = 32768

// approvalReq describes one thing a human must approve.
type approvalReq struct {
	op        string // grant|unlock|session|set-file|import|compare|delete|policy|resolve-conflict, plus the local-only reveal|overwrite|same|copy
	secrets   []string
	command   string             // what will happen; never contains the peer (it is shown separately)
	detail    string             // long text (diff, warnings) the approver must be able to read in full
	doc       *approve.ReviewDoc // optional table form of detail for the local dialog
	bind      string             // "sha256:<hex>" of the data that will be applied, or ""
	agent     string
	peer      string
	prod      bool
	mode      string // policy.ApprovalUserPresence | policy.ApprovalDevice
	localOnly bool   // never offered to the phone
	session   bool   // the phone may answer "allow and open a work session"
	startup   bool   // the start-up unlock, right after the device key was loaded
}

// approvalRes is the outcome: choice is allow|session, by is "hello" | "paste:<dev>" | "remote:<dev>".
type approvalRes struct{ choice, by string }

// preapproval is a phone decision that arrived after the caller left; the next identical request
// (same op, secrets, command and bound data) consumes it.
type preapproval struct {
	res approvalRes
	exp time.Time
}

// pendingReq is one request open on the phone. Guarded by Broker.rmu.
type pendingReq struct {
	key       string
	rq        approvalReq
	p         remote.Pending
	published bool // visible in the phone view
	waiters   int  // callers currently blocked on it
	closed    bool
	done      chan struct{} // closed together with closed = true
	res       approvalRes
	err       error
}

var errNoChannel = errors.New("không có kênh duyệt: màn hình đang khóa và chưa ghép điện thoại (kg device pair)")

// errLocalOnlyLocked: the operation is never offered to the phone (it must be approved at this
// machine), so a paired phone does not help while the screen is locked.
var errLocalOnlyLocked = errors.New("không có kênh duyệt: thao tác này chỉ duyệt tại máy (không gửi điện thoại), màn hình đang khóa: mở khóa màn hình rồi chạy lại")

// newPendingErr is the client-facing error of a request that is still open on the phone.
func newPendingErr(rid string) error {
	short := rid
	if len(short) > 6 {
		short = short[:6]
	}
	return &cmdErr{wire.CodePending, fmt.Sprintf("đang chờ duyệt trên điện thoại (yêu cầu %s); duyệt xong chạy lại lệnh", short)}
}

// isPending reports whether err is the "still waiting for the phone" outcome.
func isPending(err error) bool {
	var ce *cmdErr
	return errors.As(err, &ce) && ce.code == wire.CodePending
}

// refused turns an approval failure into the client error: pending passes through, anything else is a denial.
func refused(err error, what string) error {
	if isPending(err) {
		return err
	}
	return fail(wire.CodeDenied, "%s bị từ chối: %v", what, err)
}

// apprName is the audit "approval" value for who approved.
func apprName(by string) string {
	if strings.HasPrefix(by, "remote:") || strings.HasPrefix(by, "paste:") || by == byTTYPassword {
		return by
	}
	return policy.ApprovalUserPresence
}

type noteKey struct{}

func withNote(ctx context.Context, f func(string)) context.Context {
	return context.WithValue(ctx, noteKey{}, f)
}

func note(ctx context.Context, msg string) {
	if f, ok := ctx.Value(noteKey{}).(func(string)); ok {
		f(msg)
	}
}

// sanitize makes everything shown to a human safe and fixes the request key.
func (rq *approvalReq) sanitize() {
	ss := make([]string, len(rq.secrets))
	for i, s := range rq.secrets {
		ss[i] = approve.Sanitize(s, 200)
	}
	rq.secrets = ss
	rq.command = approve.Sanitize(rq.command, approve.MaxPrompt)
	rq.agent = approve.Sanitize(rq.agent, 200)
	rq.peer = approve.Sanitize(rq.peer, 300)
	if rq.mode == "" {
		rq.mode = policy.ApprovalUserPresence
	}
	if len(rq.detail) > maxDetail {
		rq.localOnly = true // never ask the phone to approve text it cannot display in full
	}
}

// key identifies "the same request" across a re-run: op, secrets, command and the bound data.
func (rq approvalReq) key() string {
	ss := append([]string(nil), rq.secrets...)
	sort.Strings(ss)
	h := sha256.Sum256([]byte(rq.op + "\x00" + strings.Join(ss, "\x00") + "\x00" + rq.command + "\x00" + rq.bind))
	return hex.EncodeToString(h[:])
}

// prompt is the text of the local (Windows Hello) prompt.
func (rq approvalReq) prompt() string {
	cmd := rq.command
	if rq.peer != "" && rq.op != "grant" {
		cmd += ", yêu cầu từ " + rq.peer
	}
	if len(rq.secrets) > 0 {
		return "KeyGate: cho phép dùng secret " + strings.Join(rq.secrets, ", ") + " cho lệnh: " + cmd
	}
	return "KeyGate: " + cmd
}

// reviewText is the long text of the local Review dialog: who asks, then the detail.
func (rq approvalReq) reviewText() string {
	who, chain := rq.requester()
	s := "Ai yêu cầu: " + who
	if chain != "" {
		s += ", chạy từ " + chain
	}
	return s + "\n" + rq.detail
}

// requester names the process that asked (and the agent it claims to be) and its ancestors.
func (rq approvalReq) requester() (who, chain string) {
	who = "(không rõ tiến trình)"
	if rq.peer != "" {
		who, chain = peerParts(rq.peer)
	}
	if rq.agent != "" {
		who += ", agent " + rq.agent
	}
	return who, chain
}

// DocReviewer is implemented by prompters that can show a ReviewDoc as a table.
type DocReviewer interface {
	ReviewDoc(ctx context.Context, title string, doc approve.ReviewDoc) error
}

func (b *Broker) review(ctx context.Context, rq approvalReq) error {
	title := "KeyGate: " + rq.command
	if dr, ok := b.cfg.Prompt.(DocReviewer); ok && rq.doc != nil {
		doc := *rq.doc
		doc.Requester, doc.Chain = rq.requester()
		doc.Text = rq.reviewText()
		return dr.ReviewDoc(ctx, title, doc)
	}
	return b.cfg.Prompt.Review(ctx, title, rq.reviewText())
}

// humanApprove asks a human and reports who approved. The local prompt (Hello, or the pasted device
// signature for `approval: device` without a phone) and the phone race each other; a locked screen
// goes to the phone at once, otherwise the phone is offered the request after Config.RemoteDelay.
// With a phone paired and nobody answering within Config.ApprovalWait the call returns a pending
// error and the request stays open: a later decision is kept for the next identical request.
// s may be nil only for the unlock request. A successful approval counts as human activity.
func (b *Broker) humanApprove(ctx context.Context, s *session, rq approvalReq) (approvalRes, error) {
	rq.sanitize()
	key := rq.key()
	if res, ok := b.takePreapproved(key); ok {
		b.touch()
		return res, nil
	}
	localOK := rq.mode != policy.ApprovalDevice && !b.cfg.ScreenLocked()
	remoteOK := !rq.localOnly && b.remoteReady()
	pasteOK := rq.mode == policy.ApprovalDevice && s != nil && !remoteOK
	switch {
	case remoteOK:
		return b.approveRemote(ctx, s, rq, key, localOK)
	case localOK || pasteOK:
		return b.approveLocal(ctx, s, rq)
	}
	if rq.localOnly && rq.mode != policy.ApprovalDevice && b.cfg.ScreenLocked() {
		return approvalRes{}, errLocalOnlyLocked
	}
	return approvalRes{}, errNoChannel
}

// approveLocal is the human at this machine: Review (long detail), then Hello; user-presence falls
// back to the pasted device signature on systems without it.
func (b *Broker) approveLocal(ctx context.Context, s *session, rq approvalReq) (approvalRes, error) {
	select {
	case b.apprSem <- struct{}{}:
		defer func() { <-b.apprSem }()
	case <-ctx.Done():
		return approvalRes{}, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, b.cfg.ApprovalWait)
	defer cancel()
	if rq.mode != policy.ApprovalDevice {
		prompt := rq.prompt()
		if b.cfg.OnPrompt != nil {
			b.cfg.OnPrompt(prompt)
		}
		if rq.detail != "" {
			if err := b.review(ctx, rq); err != nil {
				return approvalRes{}, err
			}
		}
		err := b.cfg.Approver.Approve(ctx, prompt)
		if err == nil {
			b.touch()
			return approvalRes{choice: "allow", by: "hello"}, nil
		}
		if !errors.Is(err, approve.ErrUnsupported) || rq.startup {
			return approvalRes{}, err
		}
		if res, ok, err := b.approveByTTYPassword(ctx, prompt); ok {
			return res, err
		}
		if s == nil {
			return approvalRes{}, err
		}
	}
	if s == nil {
		return approvalRes{}, errors.New("approval device cần vault đã mở")
	}
	st := s.st
	d := &approve.Device{
		Vault: st.Vault(), Self: st.ID.Dev, ReadLine: b.cfg.Prompt.ReadLine, Out: b.out(),
		Pubs: func() map[string]ed25519.PublicKey {
			m := map[string]ed25519.PublicKey{}
			for _, dv := range st.Members().KeyHolders() { // an approver phone never approves by pasted signature
				m[dv.ID] = dv.EdPub
			}
			return m
		},
		Now: b.cfg.Now,
	}
	if err := d.ApproveSecret(ctx, strings.Join(rq.secrets, ", "), rq.command); err != nil {
		return approvalRes{}, err
	}
	b.touch()
	return approvalRes{choice: "allow", by: "paste:" + d.Signer}, nil
}

type localResult struct {
	res approvalRes
	err error
}

// approveRemote races the local prompt (when available) against the phone.
func (b *Broker) approveRemote(ctx context.Context, s *session, rq approvalReq, key string, localOK bool) (approvalRes, error) {
	pr, err := b.joinPending(rq, key)
	if err != nil {
		return approvalRes{}, err
	}
	wctx, wcancel := context.WithTimeout(ctx, b.cfg.ApprovalWait)
	defer wcancel()
	lctx, lcancel := context.WithCancel(wctx)
	defer lcancel()

	var localCh chan localResult
	var delay <-chan time.Time
	if localOK {
		localCh = make(chan localResult, 1)
		go func() {
			res, err := b.approveLocal(lctx, s, rq)
			localCh <- localResult{res, err}
		}()
		t := time.NewTimer(b.cfg.RemoteDelay)
		defer t.Stop()
		delay = t.C
	} else {
		b.publish(pr)
	}
	// stopLocal cancels the local prompt and waits until it released the prompt lock.
	stopLocal := func() {
		lcancel()
		if localCh != nil {
			<-localCh
			localCh = nil
		}
	}
	noted := false
	for {
		if !noted && b.isPublished(pr) {
			noted = true
			note(ctx, fmt.Sprintf("đang chờ duyệt trên điện thoại (KeyGate, yêu cầu %s)", shortRID(pr.p.RID)))
		}
		select {
		case lr := <-localCh:
			localCh = nil
			if lr.err == nil {
				res, err := b.finishPending(pr, lr.res, nil)
				b.leavePending(pr)
				return res, err
			}
			b.publish(pr) // Hello refused or expired: the phone may still answer
		case <-delay:
			delay = nil
			b.publish(pr)
		case <-pr.done:
			stopLocal()
			b.leavePending(pr)
			return pr.res, pr.err
		case <-wctx.Done():
			stopLocal()
			return b.abandonPending(ctx, pr)
		}
	}
}

func shortRID(rid string) string {
	if len(rid) > 6 {
		return rid[:6]
	}
	return rid
}

func (b *Broker) takePreapproved(key string) (approvalRes, bool) {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	p, ok := b.preapproved[key]
	if !ok {
		return approvalRes{}, false
	}
	delete(b.preapproved, key)
	if !p.exp.After(b.cfg.Now()) {
		return approvalRes{}, false
	}
	return p.res, true
}

// remoteReady reports whether a phone can be asked: a mailbox and at least one approver device.
func (b *Broker) remoteReady() bool {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	return b.mailbox != nil && b.mstate != nil && len(b.mstate.Approvers()) > 0
}

// sweepLocked drops expired requests and decisions. The caller holds rmu.
func (b *Broker) sweepLocked(now time.Time) {
	for k, p := range b.preapproved {
		if !p.exp.After(now) {
			delete(b.preapproved, k)
		}
	}
	for _, pr := range b.pending {
		if now.Unix() >= pr.p.Exp {
			b.closeLocked(pr, approvalRes{}, errors.New("yêu cầu đã hết hạn"))
		}
	}
}

// closeLocked finishes pr (idempotent). The caller holds rmu.
func (b *Broker) closeLocked(pr *pendingReq, res approvalRes, err error) {
	if pr.closed {
		return
	}
	pr.closed, pr.res, pr.err = true, res, err
	close(pr.done)
	delete(b.pending, pr.key)
}

// joinPending reuses the open request with the same key or creates one.
func (b *Broker) joinPending(rq approvalReq, key string) (*pendingReq, error) {
	now := b.cfg.Now()
	b.rmu.Lock()
	defer b.rmu.Unlock()
	b.sweepLocked(now)
	if pr, ok := b.pending[key]; ok {
		pr.waiters++
		return pr, nil
	}
	if len(b.pending) >= b.cfg.MaxPending {
		return nil, errors.New("quá nhiều yêu cầu đang chờ duyệt")
	}
	choices := []string{"deny", "allow"}
	if rq.session {
		choices = append(choices, "session")
	}
	pr := &pendingReq{key: key, rq: rq, waiters: 1, done: make(chan struct{}), p: remote.Pending{
		RID: remote.NewID(), Op: rq.op, Secrets: append([]string{}, rq.secrets...), Command: rq.command, Detail: rq.detail,
		Bind: rq.bind, Agent: rq.agent, Peer: rq.peer, Prod: rq.prod, Created: now.Unix(),
		Exp: now.Add(b.cfg.PendingTTL).Unix(), Choices: choices,
	}}
	b.pending[key] = pr
	return pr, nil
}

// publish makes pr visible on the phone (and asks for a push the first time).
func (b *Broker) publish(pr *pendingReq) {
	b.rmu.Lock()
	if pr.closed || pr.published {
		b.rmu.Unlock()
		return
	}
	pr.published = true
	b.pushNext = true
	b.dirty = true
	b.fastUntil = time.Now().Add(2 * time.Minute)
	b.rmu.Unlock()
	b.wake()
	b.changed()
}

func (b *Broker) isPublished(pr *pendingReq) bool {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	return pr.published
}

// publishedCount is the number of requests visible on the phone.
func (b *Broker) publishedCount() int {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	n := 0
	for _, pr := range b.pending {
		if pr.published && !pr.closed {
			n++
		}
	}
	return n
}

func (b *Broker) leavePending(pr *pendingReq) {
	b.rmu.Lock()
	pr.waiters--
	b.rmu.Unlock()
}

// finishPending closes pr with the local result unless something decided first; it returns the
// effective outcome.
func (b *Broker) finishPending(pr *pendingReq, res approvalRes, err error) (approvalRes, error) {
	b.rmu.Lock()
	wasOpen := !pr.closed
	b.closeLocked(pr, res, err)
	res, err = pr.res, pr.err
	b.rmu.Unlock()
	if wasOpen {
		b.markDirty()
		b.changed()
	}
	return res, err
}

// abandonPending ends a wait that timed out or whose caller left. A published request stays open
// for a later decision.
func (b *Broker) abandonPending(ctx context.Context, pr *pendingReq) (approvalRes, error) {
	b.rmu.Lock()
	pr.waiters--
	if pr.closed {
		res, err := pr.res, pr.err
		b.rmu.Unlock()
		return res, err
	}
	published := pr.published
	if !published && pr.waiters <= 0 {
		b.closeLocked(pr, approvalRes{}, errors.New("hủy"))
	}
	b.rmu.Unlock()
	if published {
		return approvalRes{}, newPendingErr(pr.p.RID)
	}
	if ctx.Err() != nil {
		return approvalRes{}, fmt.Errorf("xác nhận quá hạn hoặc bị hủy: %w", ctx.Err())
	}
	return approvalRes{}, fmt.Errorf("xác nhận quá hạn hoặc bị hủy: %w", context.DeadlineExceeded)
}

// decide applies a decision to the open request rid. A remote decision (local false) must carry the
// request's exact digest; local is the tray's own Hello-approved path. ok is false when the decision is
// not acceptable (unknown rid, closed, digest or choice mismatch).
func (b *Broker) decide(rid, digest, choice, by string, local bool) (pr *pendingReq, ok bool) {
	now := b.cfg.Now()
	b.rmu.Lock()
	b.sweepLocked(now)
	for _, c := range b.pending {
		if c.p.RID == rid {
			pr = c
			break
		}
	}
	if pr == nil || pr.closed || !pr.published || (!local && digest != pr.p.Digest()) {
		b.rmu.Unlock()
		return nil, false
	}
	okChoice := false
	for _, c := range pr.p.Choices {
		okChoice = okChoice || c == choice
	}
	if !okChoice {
		b.rmu.Unlock()
		return nil, false
	}
	var res approvalRes
	var err error
	if choice == "deny" {
		err = fmt.Errorf("%w (từ chối trên %s)", approve.ErrNotVerified, by)
	} else {
		res = approvalRes{choice: choice, by: by}
	}
	nobody := pr.waiters <= 0
	if nobody && err == nil && pr.rq.op != "unlock" {
		b.preapproved[pr.key] = preapproval{res: res, exp: now.Add(b.cfg.PreapprovalTTL)}
	}
	b.closeLocked(pr, res, err)
	b.dirty = true
	b.rmu.Unlock()
	b.changed()
	if nobody && err == nil && pr.rq.op == "unlock" {
		// Nobody waits for the unlock any more: perform it now (the phone decision is the approval).
		if e := b.unlockNow(by, choice == "session"); e != nil {
			b.logf("mở khóa theo quyết định điện thoại lỗi: %v", e)
		}
	}
	return pr, true
}

// unlockNow opens the vault with the process identity after an approval that nobody was waiting on,
// optionally opening a work session.
func (b *Broker) unlockNow(by string, withSession bool) error {
	// Never block the remote loop: unlockMu is held for the whole wait of an unlock request, whose
	// decision this same loop has to deliver.
	if !b.unlockMu.TryLock() {
		return errors.New("đang chờ duyệt mở khóa: duyệt yêu cầu mở khóa đang chờ")
	}
	defer b.unlockMu.Unlock()
	b.mu.Lock()
	s := b.sess
	b.mu.Unlock()
	if s == nil {
		var err error
		if s, err = b.openStore(); err != nil {
			return err
		}
	}
	if withSession && !b.SessionOpen() {
		b.openSession(s, by)
	}
	return nil
}

// ApprovePendingLocal walks the requests published to the phone and lets the user approve them at
// this machine (tray menu): Review, then Hello. Cancelling a Review stops the walk.
func (b *Broker) ApprovePendingLocal(ctx context.Context) error {
	b.rmu.Lock()
	var list []*pendingReq
	for _, pr := range b.pending {
		if pr.published && !pr.closed {
			list = append(list, pr)
		}
	}
	b.rmu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].p.Created < list[j].p.Created })
	for _, pr := range list {
		p := pr.p
		text := fmt.Sprintf("Loại: %s\r\nSecret: %s\r\nLệnh: %s\r\nTừ: %s %s\r\n", p.Op, strings.Join(p.Secrets, ", "), p.Command, p.Agent, p.Peer)
		if p.Detail != "" {
			text += "\r\n" + p.Detail
		}
		if err := b.cfg.Prompt.Review(ctx, "KeyGate: "+p.Command, text); err != nil {
			return nil
		}
		if b.cfg.OnPrompt != nil {
			b.cfg.OnPrompt(pr.rq.prompt())
		}
		select {
		case b.apprSem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		err := b.cfg.Approver.Approve(ctx, pr.rq.prompt())
		<-b.apprSem
		if err != nil {
			b.logf("duyệt tại máy bị từ chối: %v", err)
			continue
		}
		b.touch()
		b.decide(p.RID, "", "allow", "hello", true)
	}
	return nil
}
