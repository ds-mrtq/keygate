package store

import (
	"errors"

	"keygate/internal/kcrypto"
)

// Typed verification errors (DESIGN.md sec 5, 6, 7). Use errors.Is.
var (
	// ErrBadSignature: record/checkpoint content does not match its Ed25519 signature (or is malformed).
	ErrBadSignature = kcrypto.ErrBadSignature
	// ErrUnknownDevice: record from a device not in members (or beyond a revoked device's last_seq), or member event not owner-signed.
	ErrUnknownDevice = errors.New("keygate: unknown device")
	// ErrBrokenChain: prev hash mismatch, seq gap or fork inside one device log / member chain.
	ErrBrokenChain = errors.New("keygate: broken chain")
	// ErrRollback: channel highest seq is below the local high-water mark.
	ErrRollback = errors.New("keygate: channel rolled back")
	// ErrHidden: a valid checkpoint proves records exist that the channel withholds.
	ErrHidden = errors.New("keygate: channel hides updates")
	// ErrFork: two channels present different vault states.
	ErrFork = errors.New("keygate: channels disagree (fork)")
	// ErrConflict: item has two or more heads.
	ErrConflict = errors.New("keygate: item in conflict")

	ErrNotFound   = errors.New("keygate: item not found")
	ErrDeleted    = errors.New("keygate: item deleted")
	ErrNoKey      = errors.New("keygate: no vault key for this epoch")
	ErrLocalState = errors.New("keygate: local state missing or tampered")
	ErrWrongKeys  = errors.New("keygate: password/paper key do not match this vault")
	ErrNotOwner   = errors.New("keygate: owner key does not match vault owner")
	ErrNotMember  = errors.New("keygate: this device is not an active member")
	ErrExists     = errors.New("keygate: already initialised")
	// ErrPin: the channel's genesis does not match the pin shown by a trusted device.
	ErrPin = errors.New("keygate: genesis pin mismatch (channel presents a different vault)")
	// ErrForkChannel: a line we hold at some position differs from the one already on the channel.
	ErrForkChannel = errors.New("keygate: channel holds a different line at a position we pushed")
)
