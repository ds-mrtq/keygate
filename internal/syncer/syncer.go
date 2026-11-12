// Package syncer runs DESIGN.md sec 7 sync over any transport.Transport:
// pull -> verify -> append locally; push own new data; write own checkpoint.
// The channel is never trusted: every check happens in store.Ingest.
package syncer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"keygate/internal/store"
	"keygate/internal/transport"
)

// Typed errors re-exported from store so callers need one import.
var (
	ErrBadSignature  = store.ErrBadSignature
	ErrUnknownDevice = store.ErrUnknownDevice
	ErrBrokenChain   = store.ErrBrokenChain
	ErrRollback      = store.ErrRollback
	ErrHidden        = store.ErrHidden
	ErrFork          = store.ErrFork
	ErrForkChannel   = store.ErrForkChannel
)

// Syncer syncs one Store with one channel.
type Syncer struct {
	Store *store.Store
	T     transport.Transport
	Now   func() time.Time // defaults to time.Now
}

// Result summarises a sync.
type Result struct {
	Pulled store.IngestResult
	Pushed struct{ Records, Members int }
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Sync pulls and verifies, pushes pending own data, then writes and pushes the checkpoint.
// On verification failure nothing is written locally and nothing is pushed.
// Cursors are per channel (T.Name()), so a second, empty channel is populated by pushing.
func (s *Syncer) Sync(ctx context.Context) (Result, error) {
	var res Result
	ch := s.T.Name()
	snap, err := s.T.Pull(ctx, s.Store.Since(ch))
	if err != nil {
		return res, fmt.Errorf("pull %s: %w", ch, err)
	}
	res.Pulled, err = s.Store.IngestFrom(ch, snap)
	if err != nil {
		return res, err
	}
	var full *transport.Snapshot // lazily pulled to compare lines the channel already holds
	exists := func(check func(transport.Snapshot) bool) error {
		if full == nil {
			f, err := s.T.Pull(ctx, transport.Since{})
			if err != nil {
				return fmt.Errorf("pull %s: %w", ch, err)
			}
			full = &f
		}
		if !check(*full) {
			return fmt.Errorf("%w (%s)", ErrForkChannel, ch)
		}
		return nil
	}
	// members first so other devices can resolve the signer of our records
	firstM, mlines := s.Store.PendingMembers(ch)
	for i, l := range mlines {
		n := firstM + i
		err := s.T.PushMember(ctx, n, l)
		if errors.Is(err, transport.ErrExists) {
			err = exists(func(f transport.Snapshot) bool { return n < len(f.Members) && bytes.Equal(f.Members[n], l) })
		}
		if err != nil {
			return res, fmt.Errorf("push members: %w", err)
		}
		res.Pushed.Members++
	}
	firstS, lines := s.Store.PendingOwnLines(ch)
	dev := s.Store.ID.Dev
	for i, l := range lines {
		seq := firstS + uint64(i)
		err := s.T.PushLog(ctx, dev, seq, l)
		if errors.Is(err, transport.ErrExists) {
			err = exists(func(f transport.Snapshot) bool {
				ls := f.Logs[dev]
				return seq >= 1 && seq <= uint64(len(ls)) && bytes.Equal(ls[seq-1], l)
			})
		}
		if err != nil {
			return res, fmt.Errorf("push log: %w", err)
		}
		res.Pushed.Records++
	}
	cp, err := s.Store.WriteCheckpoint(s.now())
	if err != nil {
		return res, err
	}
	if err := s.T.PushCheckpoint(ctx, dev, cp); err != nil {
		return res, fmt.Errorf("push checkpoint: %w", err)
	}
	if err := s.Store.MarkPushed(ch, firstS+uint64(len(lines))-1, uint64(firstM+len(mlines))); err != nil {
		return res, err
	}
	return res, nil
}

// VerifyVia pulls the full state from both channels, verifies each from scratch and compares
// fingerprints. Different state -> ErrFork. Either channel failing verification returns that error.
func VerifyVia(ctx context.Context, st *store.Store, primary, secondary transport.Transport) (string, error) {
	fp := func(t transport.Transport) (string, error) {
		snap, err := t.Pull(ctx, transport.Since{})
		if err != nil {
			return "", fmt.Errorf("pull %s: %w", t.Name(), err)
		}
		f, err := st.ViewFingerprint(snap)
		if err != nil {
			return "", fmt.Errorf("%s: %w", t.Name(), err)
		}
		return f, nil
	}
	a, err := fp(primary)
	if err != nil {
		return "", err
	}
	b, err := fp(secondary)
	if err != nil {
		return "", err
	}
	if a != b {
		return "", fmt.Errorf("%w: %s says %q, %s says %q", ErrFork, primary.Name(), a, secondary.Name(), b)
	}
	return a, nil
}
