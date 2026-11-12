// Package channel builds the sync transport named by vault.json / flags and runs a sync.
package channel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"strings"

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

var pairCodeRE = regexp.MustCompile(`^[A-Z2-7]{8}$`)

// NormalizePairCode upper-cases the 8-character pairing code shown on the phone and drops spaces.
func NormalizePairCode(pair string) string {
	return strings.ToUpper(strings.Join(strings.Fields(pair), ""))
}

// FetchPair downloads (and consumes) the registration code a phone published on the relay under
// the 8-character pairing code, with the origin of that publish request. It needs only the device
// identity, no vault lock or owner keys.
func FetchPair(ctx context.Context, cfg store.VaultConfig, signer transport.Signer, pair string) (string, relay.Origin, error) {
	pair = NormalizePairCode(pair)
	if !pairCodeRE.MatchString(pair) {
		return "", relay.Origin{}, errors.New("mã ghép gồm 8 ký tự A-Z, 2-7 (hiện trên điện thoại)")
	}
	if cfg.RelayURL == "" {
		return "", relay.Origin{}, errors.New("vault chưa gắn relay: kg channel add --relay-url …")
	}
	raw, o, err := relay.New(cfg.RelayURL, cfg.Vault, signer, nil).GetPair(ctx, pair)
	if err != nil {
		return "", o, err
	}
	return strings.TrimSpace(string(raw)), o, nil
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
