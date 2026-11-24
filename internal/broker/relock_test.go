package broker

import (
	"context"
	"testing"
	"time"

	"keygate/internal/approve"
	"keygate/internal/broker/wire"
)

// TestNoPresenceLockedVaultStaysLocked: on a system without user-presence (Linux), `kg lock`
// followed by a client command from a process without a terminal must not open the vault again.
// docs/DESIGN.md ("Mở khóa"): after a lock, unlocking needs a human (the device password typed at the
// broker's terminal on Linux). The broker keeps the device identity in RAM after start-up, so an
// ErrUnsupported approval must not count as one.
func TestNoPresenceLockedVaultStaysLocked(t *testing.T) {
	f := newFixtureWith(t, 0, time.Hour, func(c *Config) {
		c.Approver = approve.Func(func(context.Context, string) error { return approve.ErrUnsupported })
		c.ApprovalWait = 2 * time.Second
	})
	ctx := context.Background()
	if err := f.cli.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.cli.List(ctx); err == nil || code(err) != wire.CodeLocked {
		t.Fatalf("list after lock = %v (code %q); want a %q refusal, the vault must stay locked", err, code(err), wire.CodeLocked)
	}
	if st, err := f.cli.Status(ctx); err != nil || st.Unlocked {
		t.Fatalf("status after lock and list: unlocked=%v err=%v; want locked", st.Unlocked, err)
	}
}
