package store

import (
	"crypto/ed25519"
	"errors"

	"keygate/internal/kcrypto"
	"keygate/internal/members"
)

// AddDevice appends an add event for b and a same-epoch epoch event wrapping the current vault key
// for the new device. owner is the owner signing key (from recovery.Derive).
func (s *Store) AddDevice(owner ed25519.PrivateKey, b members.AddBody) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.v.ms
	if err := checkOwner(st, owner); err != nil {
		return err
	}
	if st.PendingEpoch {
		return errors.New("keygate: revoke awaits its epoch event")
	}
	vk, err := s.vaultKey(st.Epoch)
	if err != nil {
		return err
	}
	xraw, err := kcrypto.UnB64(b.XPub)
	if err != nil || len(xraw) != 32 {
		return errors.New("keygate: bad device x25519 key")
	}
	var xpub [32]byte
	copy(xpub[:], xraw)
	last, err := s.lastMemberEvent()
	if err != nil {
		return err
	}
	add, err := members.New(s.cfg.Vault, st.Count, last, members.TypeAdd, b, owner)
	if err != nil {
		return err
	}
	if b.Role == members.RoleApprover {
		return s.appendMembers(add)
	}
	eb, err := members.NewEpochBody(s.cfg.Vault, st.Epoch, vk, []members.Recipient{{ID: b.Dev, XPub: xpub}})
	if err != nil {
		return err
	}
	ep, err := members.New(s.cfg.Vault, st.Count+1, add, members.TypeEpoch, eb, owner)
	if err != nil {
		return err
	}
	return s.appendMembers(add, ep)
}

// RevokeDevice appends revoke(last_seq from local data) + epoch+1 (new vault key wrapped for the
// remaining devices and recovery), then re-encrypts every live item under the new epoch.
// It returns the number of items re-encrypted.
func (s *Store) RevokeDevice(owner ed25519.PrivateKey, dev, reason string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.v.ms
	if err := checkOwner(st, owner); err != nil {
		return 0, err
	}
	if dev == s.ID.Dev {
		return 0, errors.New("keygate: a device cannot revoke itself")
	}
	d, ok := st.Devices[dev]
	if !ok || d.Revoked {
		return 0, errors.New("keygate: not an active device")
	}
	last, err := s.lastMemberEvent()
	if err != nil {
		return 0, err
	}
	lastSeq := s.v.lastSeq(dev)
	lastHash := ""
	if lastSeq > 0 {
		lastHash = s.v.logs[dev].hashes[lastSeq-1]
	}
	rev, err := members.New(s.cfg.Vault, st.Count, last, members.TypeRevoke,
		members.RevokeBody{Dev: dev, Reason: reason, LastSeq: lastSeq, LastHash: lastHash}, owner)
	if err != nil {
		return 0, err
	}
	var rcpts []members.Recipient
	for _, a := range st.KeyHolders() {
		if a.ID != dev {
			rcpts = append(rcpts, members.Recipient{ID: a.ID, XPub: a.XPub})
		}
	}
	rcpts = append(rcpts, members.Recipient{ID: members.RecoveryRcpt, XPub: st.RecoveryPub})
	newEpoch := st.Epoch + 1
	vk := kcrypto.NewVaultKey()
	eb, err := members.NewEpochBody(s.cfg.Vault, newEpoch, vk, rcpts)
	if err != nil {
		return 0, err
	}
	ep, err := members.New(s.cfg.Vault, st.Count+1, rev, members.TypeEpoch, eb, owner)
	if err != nil {
		return 0, err
	}
	if err := s.appendMembers(rev, ep); err != nil {
		return 0, err
	}
	s.keys[newEpoch] = vk
	return s.reencryptLocked()
}

// RevokeApprover appends a revoke-approver event for dev signed by this device's own key (it must
// be an active key holder and dev an active approver). No epoch follows and nothing is
// re-encrypted: an approver never received a wrap of the vault key.
func (s *Store) RevokeApprover(dev, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.v.ms
	if st.PendingEpoch {
		return errors.New("keygate: revoke awaits its epoch event")
	}
	if d, ok := st.Devices[dev]; !ok || d.Revoked || d.Role != members.RoleApprover {
		return errors.New("keygate: not an active approver device")
	}
	last, err := s.lastMemberEvent()
	if err != nil {
		return err
	}
	ev, err := members.New(s.cfg.Vault, st.Count, last, members.TypeRevokeApprover,
		members.RevokeApproverBody{Dev: dev, By: s.ID.Dev, Reason: reason}, s.ID.EdPriv)
	if err != nil {
		return err
	}
	return s.appendMembers(ev)
}
