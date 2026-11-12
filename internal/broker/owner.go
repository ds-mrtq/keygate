package broker

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"keygate/internal/audit"
	"keygate/internal/broker/wire"
	"keygate/internal/channel"
	"keygate/internal/members"
	"keygate/internal/policy"
	"keygate/internal/recovery"
	"keygate/internal/store"
	"keygate/internal/transport/relay"
)

// Owner operations started from the tray (same process): the broker uses the store it already
// holds open, so neither `kg lock` nor a second store is needed. They are never offered on the
// socket. The master password and the paper key come from OwnerPrompt (a Win32 dialog of this
// process), are used once and are never stored, logged or audited.

// OwnerPrompt asks the human at this machine for the master password and the paper key; hint
// says why the previous try was refused ("" on the first try).
type OwnerPrompt func(ctx context.Context, hint string) (password, paperKey string, err error)

// ownerTries is how many times a wrong master password / paper key may be retyped.
const ownerTries = 3

// SyncWarning means the owner operation is recorded on this machine but the sync that follows
// failed (the other devices see it after the next successful sync).
type SyncWarning struct{ Err error }

func (w *SyncWarning) Error() string { return "đồng bộ sau thao tác lỗi: " + w.Err.Error() }
func (w *SyncWarning) Unwrap() error { return w.Err }

const ownerNetTimeout = 60 * time.Second

// identity is the device identity loaded by Serve (nil before).
func (b *Broker) identity() *store.Identity {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.id
}

// DeviceID is this machine's device id ("" before Serve loaded the identity).
func (b *Broker) DeviceID() string {
	if id := b.identity(); id != nil {
		return id.Dev
	}
	return ""
}

// unlockedSession is the live session, or an error while the vault is locked.
func (b *Broker) unlockedSession() (*session, error) {
	b.mu.Lock()
	s := b.sess
	b.mu.Unlock()
	if s == nil {
		return nil, fail(wire.CodeLocked, "vault đang khóa: chọn \"Mở khóa + mở phiên làm việc\" trên khay trước")
	}
	return s, nil
}

// ownerKeys derives the owner keys from what the prompt returned and checks them against the
// membership's owner key before anything is written; a typo can be retyped (ownerTries in all).
func (b *Broker) ownerKeys(ctx context.Context, s *session, owner OwnerPrompt) (*recovery.Keys, error) {
	ms := s.st.Members()
	hint := ""
	for try := 1; ; try++ {
		k, why, err := deriveOwner(ctx, ms, owner, hint)
		if err != nil || k != nil {
			return k, err
		}
		if try == ownerTries {
			return nil, fmt.Errorf("%s (đã thử %d lần)", why, ownerTries)
		}
		hint = fmt.Sprintf("%s. Nhập lại (lần %d/%d).", why, try+1, ownerTries)
	}
}

// deriveOwner runs one prompt: keys, or why the input was refused, or a hard error (cancel).
func deriveOwner(ctx context.Context, ms *members.State, owner OwnerPrompt, hint string) (*recovery.Keys, string, error) {
	pwd, pk, err := owner(ctx, hint)
	if err != nil {
		return nil, "", err
	}
	raw, err := recovery.ParsePaperKey(pk)
	if err != nil {
		return nil, "Khóa giấy sai (gõ nhầm hoặc sai mã kiểm)", nil
	}
	defer clear(raw)
	k, err := recovery.Derive(ms.Vault, pwd, ms.ArgonSalt, ms.ArgonParams, raw)
	if err != nil {
		return nil, "", err
	}
	if !ed25519.PublicKey(ms.OwnerPub).Equal(k.OwnerPub) {
		wipeKeys(k)
		return nil, "Mật khẩu chủ hoặc khóa giấy không đúng", nil
	}
	return k, "", nil
}

// writeLive runs the write phase of an owner operation while holding ownerWrite (Lock waits for
// it), only if s is still the live session: a Lock during the prompts aborts before any write.
func (b *Broker) writeLive(s *session, fn func() error) error {
	b.ownerWrite.Lock()
	defer b.ownerWrite.Unlock()
	b.mu.Lock()
	live := b.sess == s
	b.mu.Unlock()
	if !live {
		return fail(wire.CodeLocked, "vault vừa bị khóa trong lúc nhập: chưa ghi gì, hãy mở khóa rồi làm lại")
	}
	return fn()
}

func wipeKeys(k *recovery.Keys) {
	clear(k.OwnerPriv)
	clear(k.RecoveryPriv[:])
}

// ownerSync syncs over the configured channel (none configured: nothing to do).
func (b *Broker) ownerSync(ctx context.Context, s *session) error {
	if _, err := channel.Pick(s.st.Config(), ""); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, ownerNetTimeout)
	defer cancel()
	if _, err := channel.Sync(ctx, s.st, "", ""); err != nil {
		return err
	}
	t := b.cfg.Now()
	b.mu.Lock()
	b.lastSync = &t
	b.mu.Unlock()
	return nil
}

// FetchPairCode downloads the registration code a phone published under the 8-character pairing
// code (consumed on the relay: a second fetch fails) and the origin of that publish.
func (b *Broker) FetchPairCode(ctx context.Context, pair string) (string, relay.Origin, error) {
	id := b.identity()
	if id == nil {
		return "", relay.Origin{}, errors.New("broker chưa nạp khóa thiết bị")
	}
	cfg, err := store.ReadConfig(b.cfg.Home)
	if err != nil {
		return "", relay.Origin{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, ownerNetTimeout)
	defer cancel()
	return channel.FetchPair(ctx, cfg, id, pair)
}

// Seen is the relay's last-request record of every device (display only).
func (b *Broker) Seen(ctx context.Context) ([]relay.Seen, error) {
	id := b.identity()
	if id == nil {
		return nil, errors.New("broker chưa nạp khóa thiết bị")
	}
	cfg, err := store.ReadConfig(b.cfg.Home)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return channel.Seen(ctx, cfg, id)
}

// PairArgv is the audit argv of a device-add: dev, label, role and, when known, the origin of
// the pairing request as compact JSON.
func PairArgv(body members.AddBody, origin relay.Origin) []string {
	a := []string{body.Dev, body.Label, store.RoleText(body.Role)}
	if origin != (relay.Origin{}) {
		j, _ := json.Marshal(origin)
		a = append(a, string(j))
	}
	return a
}

// AddDeviceFromUI adds the device of registration code `code` to the vault (the human already
// compared the 6 words), pushes the member events signed by the owner and syncs. A *SyncWarning
// error means the device is added here but not yet published.
func (b *Broker) AddDeviceFromUI(ctx context.Context, code string, origin relay.Origin, owner OwnerPrompt) (members.AddBody, error) {
	body, err := store.DecodeRequest(code)
	if err != nil {
		return body, err
	}
	if body.Role != members.RoleApprover {
		return body, errors.New("khay chỉ ghép thiết bị duyệt (điện thoại); thiết bị đầy đủ dùng `kg device add`")
	}
	b.ownerMu.Lock()
	defer b.ownerMu.Unlock()
	s, err := b.unlockedSession()
	if err != nil {
		return body, err
	}
	if _, ok := s.st.Members().Devices[body.Dev]; ok {
		return body, fmt.Errorf("thiết bị %s đã có trong vault", body.Dev)
	}
	keys, err := b.ownerKeys(ctx, s, owner)
	if err != nil {
		return body, err
	}
	defer wipeKeys(keys)
	var warn error
	err = b.writeLive(s, func() error {
		if err := s.st.AddDevice(keys.OwnerPriv, body); err != nil {
			return err
		}
		b.audBest(s, audit.Entry{Event: audit.EvDeviceAdd, Argv: PairArgv(body, origin), Approval: "owner", Peer: "khay hệ thống"})
		b.logf("đã thêm thiết bị %s (%s, vai trò %s)", body.Dev, body.Label, store.RoleText(body.Role))
		pctx, cancel := context.WithTimeout(ctx, ownerNetTimeout)
		err := channel.PushMembersAsOwner(pctx, s.st, "", keys.OwnerPriv)
		cancel()
		if err == nil {
			err = b.ownerSync(ctx, s)
		}
		if err != nil {
			b.logf("thêm %s: %v", body.Dev, err)
			warn = &SyncWarning{err}
		}
		b.refreshMembers(s)
		return nil
	})
	if err != nil {
		return body, err
	}
	b.changed()
	return body, warn
}

// RevokeDeviceFromUI revokes dev after a Windows Hello approval at this machine, pulling first
// and syncing after. An approver (phone) is revoked with this device's own key (revoke-approver:
// no owner keys, no new epoch, nothing re-encrypted). A key holder needs the owner keys: revoke +
// new epoch re-encrypting every live secret. It returns the number of re-encrypted secrets; a
// *SyncWarning error means the revoke is recorded here but not yet published.
func (b *Broker) RevokeDeviceFromUI(ctx context.Context, dev, reason string, owner OwnerPrompt) (int, error) {
	b.ownerMu.Lock()
	defer b.ownerMu.Unlock()
	s, err := b.unlockedSession()
	if err != nil {
		return 0, err
	}
	if dev == b.DeviceID() {
		return 0, errors.New("không thu hồi được chính máy này")
	}
	d, ok := s.st.Members().Devices[dev]
	if !ok || d.Revoked {
		return 0, fmt.Errorf("%s không phải thiết bị đang hoạt động của vault", dev)
	}
	if _, err := b.humanApprove(ctx, s, approvalReq{op: "device-revoke", localOnly: true, peer: "khay hệ thống", mode: policy.ApprovalUserPresence,
		command: fmt.Sprintf("THU HỒI thiết bị %s (%s)", dev, d.Label)}); err != nil {
		b.audBest(s, audit.Entry{Event: audit.EvDeny, Argv: []string{dev}, Approval: "device-revoke-refused", Peer: "khay hệ thống"})
		return 0, refused(err, "thu hồi thiết bị")
	}
	approver := d.Role == members.RoleApprover
	var keys *recovery.Keys
	if !approver { // a key holder had the vault key: owner-signed revoke + new epoch
		if keys, err = b.ownerKeys(ctx, s, owner); err != nil {
			return 0, err
		}
		defer wipeKeys(keys)
	}
	var n int
	var warn error
	err = b.writeLive(s, func() error {
		if err := b.ownerSync(ctx, s); err != nil {
			return fmt.Errorf("đồng bộ trước khi thu hồi thất bại: %w", err)
		}
		var err error
		if approver {
			err = s.st.RevokeApprover(dev, reason)
		} else {
			n, err = s.st.RevokeDevice(keys.OwnerPriv, dev, reason)
		}
		if err != nil {
			return err
		}
		warn = b.afterRevoke(ctx, s, d, n)
		return nil
	})
	if err != nil {
		return 0, err
	}
	b.changed()
	return n, warn
}

// afterRevoke audits and logs a recorded revoke, then syncs (a failure is the returned warning).
func (b *Broker) afterRevoke(ctx context.Context, s *session, d *members.Device, n int) error {
	dev := d.ID
	if d.Role == members.RoleApprover {
		b.audBest(s, audit.Entry{Event: audit.EvDeviceRevoke, Argv: []string{dev, d.Label}, Approval: "user-presence", Peer: "khay hệ thống"})
		b.logf("đã thu hồi thiết bị duyệt %s (%s), ký bằng khóa thiết bị này; không đổi epoch", dev, d.Label)
	} else {
		b.audBest(s, audit.Entry{Event: audit.EvDeviceRevoke, Argv: []string{dev, d.Label}, Approval: "user-presence+owner", Peer: "khay hệ thống"})
		b.logf("đã thu hồi thiết bị %s (%s), mã hóa lại %d secret theo epoch %d", dev, d.Label, n, s.st.Epoch())
		var names []string
		for _, it := range s.st.List() {
			if !it.Deleted && it.Name != "" {
				names = append(names, it.Name)
			}
		}
		if len(names) > 0 {
			sort.Strings(names)
			b.logf("thiết bị %s có thể đã giải mã các secret sau; hãy đổi giá trị ở hệ thống đích: %s", dev, strings.Join(names, ", "))
		}
	}
	var warn error
	if err := b.ownerSync(ctx, s); err != nil {
		b.logf("thu hồi %s: %v", dev, err)
		warn = &SyncWarning{err}
	}
	b.refreshMembers(s)
	return warn
}
