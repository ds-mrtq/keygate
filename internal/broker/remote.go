package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"keygate/internal/api"
	"keygate/internal/audit"
	"keygate/internal/fsx"
	"keygate/internal/kcrypto"
	"keygate/internal/members"
	"keygate/internal/policy"
	"keygate/internal/remote"
	"keygate/internal/store"
	"keygate/internal/transport/relay"
)

// Mailbox is the broker's side of the relay channel to approver devices.
type Mailbox interface {
	PutView(ctx context.Context, to string, body []byte, push bool) error
	GetMsgs(ctx context.Context) ([]relay.Msg, error)
	DeleteMsg(ctx context.Context, id string) error
}

// defaultMailbox is the relay client of vault.json's relay_url (none without one).
func defaultMailbox(cfg store.VaultConfig, id *store.Identity) Mailbox {
	if cfg.RelayURL == "" {
		return nil
	}
	return relay.New(cfg.RelayURL, cfg.Vault, id, nil)
}

// viewCache keeps the parts of the phone view that are costly to build (a ledger read).
type viewCache struct {
	ok       bool
	secrets  []remote.ViewSecret
	audit    []remote.ViewAudit
	policyOK bool
}

func (b *Broker) markDirty() {
	b.rmu.Lock()
	b.dirty = true
	b.rmu.Unlock()
}

// wake makes the remote loop run now.
func (b *Broker) wake() {
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

func membersMACPath(home string) string { return filepath.Join(home, "state", "members.mac") }

// membersMark is the membership position (event count and head hash) last bound to this device.
type membersMark struct {
	Genesis string `json:"genesis"`
	Count   uint64 `json:"count"`
	Head    string `json:"head"`
	MAC     string `json:"mac"`
}

func (b *Broker) membersMAC(genesis string, count uint64, head string) string {
	e := kcrypto.NewEnc(kcrypto.LabelLocalMac).LPS("members").LPS(b.vaultID).LPS(genesis).U64(count).LPS(head)
	return base64.StdEncoding.EncodeToString(kcrypto.MAC(b.id.LocalMacKey(), e.Bytes()))
}

// refreshMembers remembers the membership of the unlocked store (RAM) and binds its position
// (genesis, event count, head) to this device in state/members.mac, so a later start can trust
// members.kgl before the first unlock and notice a rolled-back file.
func (b *Broker) refreshMembers(s *session) {
	ms := s.st.Members()
	b.rmu.Lock()
	changed := b.mstate == nil || b.mstate.Count != ms.Count || len(b.mstate.Approvers()) != len(ms.Approvers())
	b.mstate = ms
	write := ms.GenesisHash != "" && b.id != nil && (ms.Count != b.markCount || ms.Head != b.markHead)
	if write {
		b.markCount, b.markHead = ms.Count, ms.Head
	}
	b.rmu.Unlock()
	if write {
		data, err := json.Marshal(membersMark{Genesis: ms.GenesisHash, Count: ms.Count, Head: ms.Head, MAC: b.membersMAC(ms.GenesisHash, ms.Count, ms.Head)})
		if err == nil {
			if err = os.MkdirAll(filepath.Dir(membersMACPath(b.cfg.Home)), 0o700); err == nil {
				err = fsx.WriteAtomic(membersMACPath(b.cfg.Home), data)
			}
		}
		if err != nil {
			b.logf("không ghi được members.mac: %v", err)
		}
	}
	if changed {
		b.markDirty()
		b.wake()
	}
}

// loadMembers reads members.kgl at start, before the first unlock, and keeps it only when it is at
// or beyond the position MAC'd by an earlier unlock on this device: same head at that count, or a
// longer chain whose prefix up to that count has the MAC'd head. A shorter file (rolled back, e.g.
// a cut `revoke`) or a wrong MAC gives no phone channel until the next unlock at this machine.
func (b *Broker) loadMembers() {
	raw, err := os.ReadFile(membersMACPath(b.cfg.Home))
	if err != nil {
		return
	}
	var mk membersMark
	if json.Unmarshal(raw, &mk) != nil || !hmac.Equal([]byte(mk.MAC), []byte(b.membersMAC(mk.Genesis, mk.Count, mk.Head))) {
		b.logf("members.mac không hợp lệ: chưa dùng kênh điện thoại cho tới lần mở khóa tại máy")
		return
	}
	lines, err := fsx.ReadLines(filepath.Join(b.cfg.Home, "members.kgl"))
	if err != nil || uint64(len(lines)) < mk.Count {
		b.logf("members.kgl ngắn hơn lần mở khóa trước: chưa dùng kênh điện thoại cho tới lần mở khóa tại máy")
		return
	}
	ms, err := members.Replay(lines)
	if err != nil || ms.GenesisHash != mk.Genesis {
		return
	}
	at := ms
	if ms.Count != mk.Count {
		if at, err = members.Replay(lines[:mk.Count]); err != nil {
			return
		}
	}
	if at.Count != mk.Count || at.Head != mk.Head {
		b.logf("members.kgl khác lần mở khóa trước: chưa dùng kênh điện thoại cho tới lần mở khóa tại máy")
		return
	}
	b.rmu.Lock()
	b.mstate, b.markCount, b.markHead = ms, mk.Count, mk.Head
	b.rmu.Unlock()
}

// approvers returns the active approver devices of the last verified membership.
func (b *Broker) approvers() []*members.Device {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	if b.mstate == nil {
		return nil
	}
	return b.mstate.Approvers()
}

func (b *Broker) approverKey(dev string) ed25519.PublicKey {
	for _, d := range b.approvers() {
		if d.ID == dev {
			return d.EdPub
		}
	}
	return nil
}

// remoteLoop exchanges messages with approver devices through the relay until ctx ends.
func (b *Broker) remoteLoop(ctx context.Context) {
	var lastPost time.Time
	backoff := time.Duration(0)
	var lastErr string
	var lastLog time.Time
	for {
		err := b.remoteTick(ctx, &lastPost)
		wait := b.cfg.RemoteSlow
		switch {
		case err != nil:
			if backoff == 0 {
				backoff = b.cfg.RemoteFast
			} else {
				backoff *= 2
			}
			if backoff > time.Minute {
				backoff = time.Minute
			}
			wait = backoff
			if msg := err.Error(); ctx.Err() == nil && (msg != lastErr || time.Since(lastLog) > time.Minute) {
				lastErr, lastLog = msg, time.Now()
				b.logf("kênh điện thoại lỗi: %v", err)
			}
		case len(b.approvers()) == 0:
			backoff = 0
			wait = b.cfg.RemoteBeat
		default:
			backoff = 0
			b.rmu.Lock()
			fast := time.Now().Before(b.fastUntil)
			b.rmu.Unlock()
			if fast || b.publishedCount() > 0 {
				wait = b.cfg.RemoteFast
			}
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-b.kick:
			t.Stop()
		case <-t.C:
		}
	}
}

func (b *Broker) remoteTick(ctx context.Context, lastPost *time.Time) error {
	b.mu.Lock()
	s := b.sess
	b.mu.Unlock()
	if s != nil {
		b.refreshMembers(s)
	}
	aps := b.approvers()
	if len(aps) == 0 {
		return nil
	}
	mb := b.mailbox
	msgs, err := mb.GetMsgs(ctx)
	if err != nil {
		return err
	}
	now := b.cfg.Now()
	b.rmu.Lock()
	for id, t := range b.seen {
		if now.Sub(t) > 24*time.Hour {
			delete(b.seen, id)
		}
	}
	b.rmu.Unlock()
	for _, m := range msgs {
		b.handleMsg(ctx, m)
		if err := mb.DeleteMsg(ctx, m.ID); err != nil {
			return err
		}
	}
	return b.postView(ctx, mb, lastPost)
}

// handleMsg verifies and applies one phone message. Anything not acceptable is dropped (the caller
// deletes the mailbox entry either way).
func (b *Broker) handleMsg(ctx context.Context, m relay.Msg) {
	from, envID, t, pt, err := remote.Open(b.vaultID, b.id.Dev, b.id.XPriv, m.Body, b.approverKey)
	if err != nil {
		b.logf("thư từ điện thoại bị bỏ: %v", err)
		return
	}
	// The relay path id is not signed: only the signed envelope id identifies a message.
	if m.ID != envID {
		b.logf("thư từ %s bị bỏ: id relay khác id đã ký", from)
		return
	}
	if !b.firstSeen("msg:" + from + "/" + envID) {
		return
	}
	now := b.cfg.Now()
	if t.Before(b.started.Truncate(time.Millisecond)) || now.Sub(t) > b.cfg.MaxMsgAge || t.After(now.Add(5*time.Minute)) {
		b.logf("thư từ %s bị bỏ: ngoài khoảng thời gian cho phép", from)
		return
	}
	b.rmu.Lock()
	b.fastUntil = time.Now().Add(2 * time.Minute)
	b.rmu.Unlock()
	var head struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(pt, &head) != nil {
		b.logf("thư từ %s bị bỏ: không phải JSON", from)
		return
	}
	switch head.Kind {
	case remote.KindDecision:
		var d remote.Decision
		if err := remote.Strict(pt, &d); err != nil {
			b.logf("quyết định từ %s bị bỏ: %v", from, err)
			return
		}
		b.handleDecision(from, d)
	case remote.KindCommand:
		var c remote.Command
		if err := remote.Strict(pt, &c); err != nil {
			b.logf("lệnh từ %s bị bỏ: %v", from, err)
			return
		}
		b.handleCommand(ctx, from, c)
	default:
		b.logf("thư từ %s bị bỏ: loại %q", from, head.Kind)
	}
}

// firstSeen records key and reports whether it was new (replay protection, kept 24 hours).
func (b *Broker) firstSeen(key string) bool {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	if _, dup := b.seen[key]; dup {
		return false
	}
	b.seen[key] = b.cfg.Now()
	return true
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (b *Broker) handleDecision(from string, d remote.Decision) {
	by := "remote:" + from
	if !digestRE.MatchString(d.Digest) {
		b.logf("quyết định từ %s bị bỏ: digest thiếu hoặc sai định dạng", from)
		return
	}
	pr, ok := b.decide(d.RID, d.Digest, d.Choice, by, false)
	if !ok {
		b.logf("quyết định từ %s bị bỏ: yêu cầu không còn mở, digest hoặc lựa chọn không khớp", from)
		return
	}
	if d.Choice == "deny" {
		b.mu.Lock()
		s := b.sess
		b.mu.Unlock()
		if s != nil {
			b.audBest(s, audit.Entry{Event: audit.EvDeny, Secret: strings.Join(pr.p.Secrets, ", "), Agent: pr.p.Agent, Peer: pr.p.Peer, Approval: by})
		}
	}
}

func (b *Broker) addResult(cid string, ok bool, msg string) {
	b.rmu.Lock()
	b.results = append(b.results, remote.CmdResult{CID: cid, OK: ok, Msg: msg, Time: b.cfg.Now().Unix()})
	if len(b.results) > 10 {
		b.results = b.results[len(b.results)-10:]
	}
	b.dirty = true
	b.rmu.Unlock()
}

type revokeArgs struct {
	Secret  string `json:"secret"`
	Pattern string `json:"pattern"`
	Path    string `json:"path"`
	All     bool   `json:"all"`
}

type phoneSetArgs struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Env      string `json:"env"`
	EnvName  string `json:"env_name"`
	TNSAlias string `json:"tns_alias"`
	User     string `json:"user"`
	Desc     string `json:"desc"`
	Value    string `json:"value"`
}

// handleCommand runs an approver-signed command. The value of a `set` never reaches a log, a result
// or the audit ledger.
func (b *Broker) handleCommand(ctx context.Context, from string, c remote.Command) {
	if c.Op == "refresh" {
		// Harmless and needed by a phone that has no view of this boot yet: no Boot check.
		b.markDirty()
		b.wake()
		return
	}
	if c.Boot != b.started.UnixMilli() {
		b.logf("lệnh %s từ %s bị bỏ: view cũ (broker đã khởi động lại)", c.Op, from)
		return
	}
	if c.CID == "" || len(c.CID) > 64 {
		b.logf("lệnh %s từ %s bị bỏ: thiếu cid", c.Op, from)
		return
	}
	by := "remote:" + from
	if !b.firstSeen("cid:" + from + "/" + c.CID) {
		b.logf("lệnh %s từ %s bị bỏ: cid đã dùng", c.Op, from)
		return
	}
	b.mu.Lock()
	s := b.sess
	b.mu.Unlock()
	fin := func(err error, okMsg string) {
		if err != nil {
			b.addResult(c.CID, false, err.Error())
			return
		}
		b.addResult(c.CID, true, okMsg)
	}
	switch c.Op {
	case "lock":
		b.Lock()
		fin(nil, "đã khóa")
	case "session-end":
		b.endSession(by)
		fin(nil, "đã kết thúc phiên")
	case "session-start":
		fin(b.unlockNow(by, true), "đã mở phiên làm việc")
	case "grant-revoke":
		var a revokeArgs
		if err := remote.Strict(c.Args, &a); err != nil || (!a.All && a.Secret == "") {
			fin(errors.New("tham số thu hồi sai"), "")
			return
		}
		n := b.revokeWhere(func(g grantEntry) bool {
			return a.All || (g.Secret == a.Secret && (a.Pattern == "" || g.Pattern == a.Pattern) && (a.Path == "" || g.Path == a.Path))
		}, by)
		fin(nil, fmt.Sprintf("đã thu hồi %d grant", n))
	case "set":
		var a phoneSetArgs
		if err := remote.Strict(c.Args, &a); err != nil {
			fin(errors.New("tham số thêm secret sai"), "")
			return
		}
		fin(b.phoneSet(s, a, by), "đã lưu: "+strings.TrimSpace(a.Name))
	default:
		fin(fmt.Errorf("lệnh lạ %q", c.Op), "")
	}
}

func (b *Broker) phoneSet(s *session, a phoneSetArgs, by string) error {
	if s == nil {
		return errors.New("vault đang khóa")
	}
	if a.Value == "" {
		return errors.New("giá trị rỗng")
	}
	r := api.SetRequest{Name: a.Name, Kind: a.Kind, Env: a.Env, Desc: a.Desc, EnvName: a.EnvName, TNSAlias: a.TNSAlias, User: a.User}
	if err := b.validateSet(&r); err != nil {
		return err
	}
	// Overwriting an existing secret is done at the machine only (DESIGN sec 9): a stolen phone must
	// not be able to replace a token or endpoint that later `kg run` calls send out.
	if b.exists(s, r.Name) {
		return errors.New("secret đã tồn tại; ghi đè chỉ làm tại máy")
	}
	if err := b.storeSecret(s, r, a.Value, audit.EvSet, "", by); err != nil {
		return errors.New("không lưu được secret")
	}
	return nil
}

// buildView assembles the phone view; s is nil while the vault is locked.
func (b *Broker) buildView(s *session, rebuild bool) remote.View {
	now := b.cfg.Now()
	b.mu.Lock()
	v := remote.View{Kind: remote.KindView, Boot: b.started.UnixMilli(), Time: now.UnixMilli(), Label: b.id.Label,
		Unlocked: s != nil}
	if b.sessID != "" {
		v.Session = &remote.ViewSession{ID: b.sessID, Start: b.sessStart.Unix()}
	}
	b.mu.Unlock()
	v.Secrets, v.Audit = []remote.ViewSecret{}, []remote.ViewAudit{}
	if s != nil {
		b.rmu.Lock()
		c := b.rview
		b.rmu.Unlock()
		if rebuild || !c.ok {
			c = b.buildViewCache(s)
			b.rmu.Lock()
			b.rview = c
			b.rmu.Unlock()
		}
		v.PolicyOK = c.policyOK
		v.Secrets, v.Audit = c.secrets, c.audit
	}
	v.Grants = b.grantViews()
	b.rmu.Lock()
	v.Pending = []remote.Pending{}
	for _, pr := range b.pending {
		if pr.published && !pr.closed {
			v.Pending = append(v.Pending, pr.p)
		}
	}
	v.Results = append([]remote.CmdResult{}, b.results...)
	b.rmu.Unlock()
	sort.Slice(v.Pending, func(i, j int) bool { return v.Pending[i].Created < v.Pending[j].Created })
	return v
}

func (b *Broker) buildViewCache(s *session) viewCache {
	now := b.cfg.Now()
	c := viewCache{ok: true, secrets: []remote.ViewSecret{}, audit: []remote.ViewAudit{}}
	_, err := b.loadPolicy(s)
	c.policyOK = err == nil
	used := map[string]int64{}
	var recent []audit.Entry
	if es, err := s.led.Show(time.Time{}); err == nil {
		since := now.Add(-7 * 24 * time.Hour)
		for _, e := range es {
			t, err := time.Parse(time.RFC3339Nano, e.Time)
			if err != nil {
				continue
			}
			if e.Event == audit.EvRun && t.Unix() > used[e.Secret] {
				used[e.Secret] = t.Unix()
			}
			if !t.Before(since) {
				recent = append(recent, e)
			}
		}
	}
	if len(recent) > 50 {
		recent = recent[len(recent)-50:]
	}
	for _, e := range recent {
		t, _ := time.Parse(time.RFC3339Nano, e.Time)
		va := remote.ViewAudit{Time: t.Unix(), Event: e.Event, Secret: e.Secret, Agent: e.Agent, Approval: e.Approval}
		if e.Exit != nil {
			va.Exit = *e.Exit
		}
		c.audit = append(c.audit, va)
	}
	for _, it := range s.st.List() {
		if it.Deleted || it.Name == "" {
			continue
		}
		c.secrets = append(c.secrets, remote.ViewSecret{Name: it.Name, Env: it.Env, Kind: it.Kind,
			Prod: policy.IsProd(it.Name, it.Env), LastUsed: used[it.Name], Conflict: it.Conflict})
	}
	sort.Slice(c.secrets, func(i, j int) bool { return c.secrets[i].Name < c.secrets[j].Name })
	return c
}

// postView seals the view for every approver and uploads it when something changed, after the
// minimum gap, or as a heartbeat.
func (b *Broker) postView(ctx context.Context, mb Mailbox, lastPost *time.Time) error {
	real := time.Now()
	b.rmu.Lock()
	due := lastPost.IsZero() || (b.dirty && real.Sub(*lastPost) >= b.cfg.RemoteMinPost) || real.Sub(*lastPost) >= b.cfg.RemoteBeat
	rebuild, push := b.dirty, b.pushNext
	if due {
		b.dirty, b.pushNext = false, false
	}
	b.rmu.Unlock()
	if !due {
		return nil
	}
	restore := func() {
		b.rmu.Lock()
		b.dirty = b.dirty || rebuild
		b.pushNext = b.pushNext || push
		b.rmu.Unlock()
	}
	b.mu.Lock()
	s := b.sess
	b.mu.Unlock()
	view := b.buildView(s, rebuild)
	raw, err := json.Marshal(view)
	if err != nil {
		restore()
		return err
	}
	now := b.cfg.Now()
	for _, d := range b.approvers() {
		line, err := remote.Seal(b.vaultID, b.id, d.ID, d.XPub, raw, now)
		if err != nil {
			restore()
			return err
		}
		if err := mb.PutView(ctx, d.ID, line, push); err != nil {
			restore()
			return err
		}
	}
	*lastPost = real
	return nil
}
