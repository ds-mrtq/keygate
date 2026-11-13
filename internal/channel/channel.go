// Package channel builds the sync transport named by vault.json / flags and runs a sync.
package channel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"keygate/internal/broker/wire"
	"keygate/internal/store"
	"keygate/internal/syncer"
	"keygate/internal/transport"
	"keygate/internal/transport/dir"
	"keygate/internal/transport/git"
	"keygate/internal/transport/relay"
)

// OwnerSigner signs relay requests with the owner key (genesis / first add events only).
type OwnerSigner struct{ Priv ed25519.PrivateKey }

// DeviceID is the relay sender id of the owner.
func (OwnerSigner) DeviceID() string { return "owner" }

// Sign signs m with the owner key.
func (o OwnerSigner) Sign(m []byte) []byte { return ed25519.Sign(o.Priv, m) }

// PushMembersAsOwner pushes pending member events to a relay signed by the owner key (genesis and
// the first add events cannot be signed by a not-yet-member device). No-op unless via (or the
// first configured channel) is the relay.
func PushMembersAsOwner(ctx context.Context, st *store.Store, via string, owner ed25519.PrivateKey) error {
	cfg := st.Config()
	if v, err := Pick(cfg, via); err != nil || v != "relay" {
		return nil
	}
	t, err := Open(cfg, "relay", OwnerSigner{owner})
	if err != nil {
		return err
	}
	first, lines := st.PendingMembers(t.Name())
	for i, l := range lines {
		err := t.PushMember(ctx, first+i, l)
		if errors.Is(err, transport.ErrExists) {
			// Same rule as the syncer: the line already there must be byte-identical, else the channel forked.
			snap, perr := t.Pull(ctx, transport.Since{Members: first + i})
			if perr != nil {
				return perr
			}
			if len(snap.Members) == 0 || !bytes.Equal(snap.Members[0], l) {
				return fmt.Errorf("%w: sự kiện thành viên %d trên kênh khác bản của ta", syncer.ErrForkChannel, first+i)
			}
			continue
		}
		if err != nil {
			return err
		}
	}
	return st.MarkPushed(t.Name(), 0, uint64(first+len(lines)))
}

// PairTTL is how long the relay keeps a pairing slot open.
const PairTTL = 10 * time.Minute

const pairPoll = 2 * time.Second

var pairB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func pairClient(cfg store.VaultConfig, signer transport.Signer) (*relay.Client, error) {
	if cfg.RelayURL == "" {
		return nil, errors.New("vault chưa gắn relay: kg channel add --relay-url …")
	}
	return relay.New(cfg.RelayURL, cfg.Vault, signer, nil), nil
}

// OpenPair opens a pairing slot on the relay (signed by this key-holding device) and returns the
// slot code, the nonce and the link the phone opens: <relay>/app/#v=<vault>&p=<pin>&c=<code>&n=<nonce>.
// The nonce (16 random bytes, base64url) lives only in the link; it binds the confirmation words
// (store.PairWords) and never reaches the relay. It needs only the device identity, no vault lock.
func OpenPair(ctx context.Context, cfg store.VaultConfig, signer transport.Signer, pin string) (code, nonce, link string, err error) {
	c, err := pairClient(cfg, signer)
	if err != nil {
		return "", "", "", err
	}
	var rb [26]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return "", "", "", err
	}
	code = pairB32.EncodeToString(rb[:10]) // 80 bits
	nonce = base64.RawURLEncoding.EncodeToString(rb[10:])
	if err := c.OpenPair(ctx, code); err != nil {
		return "", "", "", err
	}
	link = fmt.Sprintf("%s/app/#v=%s&p=%s&c=%s&n=%s", strings.TrimRight(cfg.RelayURL, "/"), cfg.Vault, pin, code, nonce)
	return code, nonce, link, nil
}

// WaitPair polls the slot opened by OpenPair every 2 seconds until the phone has published its
// registration code (consumed on the relay) with the origin of that request. It fails when the
// slot is gone (expired), after 5 consecutive network errors, or when ctx ends.
func WaitPair(ctx context.Context, cfg store.VaultConfig, signer transport.Signer, code string) (string, relay.Origin, error) {
	c, err := pairClient(cfg, signer)
	if err != nil {
		return "", relay.Origin{}, err
	}
	fails := 0
	for {
		raw, o, ready, err := c.GetPair(ctx, code)
		switch {
		case ctx.Err() != nil:
			return "", relay.Origin{}, ctx.Err()
		case errors.Is(err, relay.ErrPairGone):
			return "", relay.Origin{}, errors.New("mã ghép hết hạn (10 phút): mở lại Ghép điện thoại")
		case err != nil:
			if fails++; fails >= 5 {
				return "", relay.Origin{}, err
			}
		case ready:
			return strings.TrimSpace(string(raw)), o, nil
		default:
			fails = 0
		}
		select {
		case <-ctx.Done():
			return "", relay.Origin{}, ctx.Err()
		case <-time.After(pairPoll):
		}
	}
}

// Seen lists the last request (time, origin) of every device as the relay recorded it; nil
// without a relay.
func Seen(ctx context.Context, cfg store.VaultConfig, signer transport.Signer) ([]relay.Seen, error) {
	if cfg.RelayURL == "" {
		return nil, nil
	}
	return relay.New(cfg.RelayURL, cfg.Vault, signer, nil).Devices(ctx)
}

// Pick returns via, or the first configured channel when via is empty.
func Pick(cfg store.VaultConfig, via string) (string, error) {
	if via != "" {
		return via, nil
	}
	switch {
	case cfg.SyncDir != "":
		return "dir", nil
	case cfg.GitDir != "":
		return "git", nil
	case cfg.RelayURL != "":
		return "relay", nil
	}
	return "", errors.New("chưa cấu hình kênh đồng bộ (sync_dir, git_dir hoặc relay_url trong vault.json; dùng --via/--dir/--git-dir/--relay)")
}

// Open builds the transport for via (dir|git|relay) acting as device `self`.
func Open(cfg store.VaultConfig, via string, signer transport.Signer) (transport.Transport, error) {
	via, err := Pick(cfg, via)
	if err != nil {
		return nil, err
	}
	self := signer.DeviceID()
	switch via {
	case "dir":
		if cfg.SyncDir == "" {
			return nil, errors.New("thiếu sync_dir")
		}
		return dir.New(cfg.SyncDir, self)
	case "git":
		if cfg.GitDir == "" {
			return nil, errors.New("thiếu git_dir")
		}
		return git.New(cfg.GitDir, self)
	case "relay":
		if cfg.RelayURL == "" {
			return nil, errors.New("thiếu relay_url")
		}
		return relay.New(cfg.RelayURL, cfg.Vault, signer, nil), nil
	}
	return nil, fmt.Errorf("kênh %q không hợp lệ (dir|git|relay)", via)
}

// Sync syncs st over via; verifyVia (optional) compares fingerprints with a second channel.
func Sync(ctx context.Context, st *store.Store, via, verifyVia string) (wire.SyncResult, error) {
	cfg := st.Config()
	via, err := Pick(cfg, via)
	if err != nil {
		return wire.SyncResult{}, err
	}
	t, err := Open(cfg, via, st.ID)
	if err != nil {
		return wire.SyncResult{}, err
	}
	res, err := (&syncer.Syncer{Store: st, T: t}).Sync(ctx)
	if err != nil {
		return wire.SyncResult{}, err
	}
	out := wire.SyncResult{
		Channel: t.Name(),
		Pulled:  res.Pulled.Members + res.Pulled.Records,
		Pushed:  res.Pushed.Records + res.Pushed.Members,
	}
	if verifyVia != "" {
		t2, err := Open(cfg, verifyVia, st.ID)
		if err != nil {
			return wire.SyncResult{}, err
		}
		if _, err := syncer.VerifyVia(ctx, st, t, t2); err != nil {
			return wire.SyncResult{}, err
		}
		out.Verified = t2.Name()
	}
	out.Fingerprint = st.Fingerprint()
	return out, nil
}
