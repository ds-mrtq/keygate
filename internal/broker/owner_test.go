package broker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"keygate/internal/members"
	"keygate/internal/store"
	"keygate/internal/transport/relay"
)

// ownerFix is an unlocked broker plus an approver registration code and a counting owner prompt.
type ownerFix struct {
	*fixture
	phone *store.Identity
	code  string
	asked atomic.Int32
}

func newOwnerFix(t *testing.T) *ownerFix {
	f := newFixture(t, 0, time.Hour)
	f.put("", "ebs/test/a", "test") // one live secret to re-encrypt on revoke
	if err := f.b.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	o := &ownerFix{fixture: f, phone: store.NewIdentity("phone")}
	body := o.phone.Public()
	body.Role = members.RoleApprover
	o.code = store.RequestCode(body)
	return o
}

func (o *ownerFix) prompt(pwd, paper string) OwnerPrompt {
	return func(context.Context, string) (string, string, error) {
		o.asked.Add(1)
		return pwd, paper, nil
	}
}

func (o *ownerFix) isApprover(dev string) bool {
	for _, d := range o.b.approvers() {
		if d.ID == dev {
			return true
		}
	}
	return false
}

func (o *ownerFix) count() uint64 {
	s, err := o.b.unlockedSession()
	if err != nil {
		o.t.Fatal(err)
	}
	return s.st.Members().Count
}

func TestAddDeviceFromUI(t *testing.T) {
	o := newOwnerFix(t)
	ctx := context.Background()
	before := o.count()

	if _, err := o.b.AddDeviceFromUI(ctx, o.code, relay.Origin{}, o.prompt("sai-mat-khau-chu", o.paper)); err == nil {
		t.Fatal("wrong master password must fail")
	}
	if o.count() != before || o.isApprover(o.phone.Dev) {
		t.Fatal("a failed add must not change the membership")
	}
	if o.asked.Load() != ownerTries {
		t.Fatalf("wrong keys asked %d times, want %d retries", o.asked.Load(), ownerTries)
	}
	o.asked.Store(0)

	body, err := o.b.AddDeviceFromUI(ctx, o.code, relay.Origin{}, o.prompt("pw-pw-pw-pw-pw-pw", o.paper))
	if err != nil {
		t.Fatal(err)
	}
	if body.Dev != o.phone.Dev || !o.isApprover(o.phone.Dev) {
		t.Fatal("the new approver must be in the broker's approver list at once")
	}
	if !contains(auditEvents(t, o.fixture), "device-add") {
		t.Fatal("audit must record device-add")
	}
	if _, err := o.b.AddDeviceFromUI(ctx, o.code, relay.Origin{}, o.prompt("pw-pw-pw-pw-pw-pw", o.paper)); err == nil {
		t.Fatal("adding the same device twice must fail")
	}
	if o.asked.Load() != 1 {
		t.Fatalf("owner prompt asked %d times, want 1 (not for the duplicate)", o.asked.Load())
	}
}

func TestRevokeDeviceFromUI(t *testing.T) {
	o := newOwnerFix(t)
	ctx := context.Background()
	good := o.prompt("pw-pw-pw-pw-pw-pw", o.paper)
	if _, err := o.b.AddDeviceFromUI(ctx, o.code, relay.Origin{}, good); err != nil {
		t.Fatal(err)
	}
	o.asked.Store(0)
	before := o.count()

	o.refuse.Store(true)
	hello := o.approvals.Load()
	if _, err := o.b.RevokeDeviceFromUI(ctx, o.phone.Dev, "test", good); err == nil {
		t.Fatal("a refused Hello must stop the revoke")
	}
	if o.approvals.Load() != hello+1 || o.asked.Load() != 0 {
		t.Fatalf("Hello asked %d, owner prompt asked %d: want 1 and 0", o.approvals.Load()-hello, o.asked.Load())
	}
	if o.count() != before || !o.isApprover(o.phone.Dev) {
		t.Fatal("a refused revoke must not change the membership")
	}
	o.refuse.Store(false)

	hello = o.approvals.Load()
	if _, err := o.b.RevokeDeviceFromUI(ctx, o.b.DeviceID(), "test", good); err == nil {
		t.Fatal("revoking this machine must be refused")
	}
	if o.approvals.Load() != hello || o.asked.Load() != 0 {
		t.Fatal("revoking this machine must fail before any prompt")
	}

	s0, _ := o.b.unlockedSession()
	epoch := s0.st.Epoch()
	n, err := o.b.RevokeDeviceFromUI(ctx, o.phone.Dev, "test", good)
	if err != nil {
		t.Fatal(err)
	}
	// an approver goes with Hello only: one revoke-approver event, no owner prompt, no new epoch
	if n != 0 || o.isApprover(o.phone.Dev) || o.count() != before+1 || o.asked.Load() != 0 || s0.st.Epoch() != epoch {
		t.Fatalf("revoke approver: n=%d approver=%v count=%d asked=%d epoch=%d", n, o.isApprover(o.phone.Dev), o.count(), o.asked.Load(), s0.st.Epoch())
	}
	if ms, err := store.ReadMembers(o.home); err != nil || !ms.Devices[o.phone.Dev].Revoked {
		t.Fatalf("members.kgl after revoke-approver: %v", err)
	}
	if !contains(auditEvents(t, o.fixture), "device-revoke") {
		t.Fatal("audit must record device-revoke")
	}
	// The broker keeps working on the re-encrypted secret with the new epoch key.
	s, _ := o.b.unlockedSession()
	info, err := s.st.FindByName("ebs/test/a")
	if err != nil {
		t.Fatal(err)
	}
	if p, _, err := s.st.Get(info.Item); err != nil || p.Value != "value-ebs/test/a" {
		t.Fatalf("secret after revoke: %v", err)
	}
}

func TestOwnerOpsNeedUnlockedVault(t *testing.T) {
	o := newOwnerFix(t)
	o.b.Lock()
	if _, err := o.b.AddDeviceFromUI(context.Background(), o.code, relay.Origin{}, o.prompt("x", "y")); err == nil || o.asked.Load() != 0 {
		t.Fatal("add on a locked vault must fail before the owner prompt")
	}
}

// A lock while the owner keys are being typed aborts the operation before any write.
func TestOwnerOpLockDuringPrompt(t *testing.T) {
	o := newOwnerFix(t)
	before := o.count()
	lockThenGood := func(ctx context.Context, hint string) (string, string, error) {
		o.b.Lock()
		return "pw-pw-pw-pw-pw-pw", o.paper, nil
	}
	if _, err := o.b.AddDeviceFromUI(context.Background(), o.code, relay.Origin{}, lockThenGood); err == nil {
		t.Fatal("add must fail when the vault was locked during the prompt")
	}
	ms, err := store.ReadMembers(o.home)
	if err != nil {
		t.Fatal(err)
	}
	if ms.Count != before {
		t.Fatalf("members.kgl changed after an aborted add: %d -> %d", before, ms.Count)
	}
}

// The tray never hands the vault key to a full device.
func TestAddDeviceFromUIApproverOnly(t *testing.T) {
	o := newOwnerFix(t)
	full := store.NewIdentity("laptop-2").Public()
	if _, err := o.b.AddDeviceFromUI(context.Background(), store.RequestCode(full), relay.Origin{}, o.prompt("pw-pw-pw-pw-pw-pw", o.paper)); err == nil || o.asked.Load() != 0 {
		t.Fatal("a full device must be refused before the owner prompt")
	}
}

// A key holder (full device) still needs the owner keys and gets a new epoch.
func TestRevokeKeyHolderFromUINeedsOwner(t *testing.T) {
	o := newOwnerFix(t)
	full := store.NewIdentity("laptop-2")
	o.withStore(func(st *store.Store) {
		if err := st.AddDevice(o.keys.OwnerPriv, full.Public()); err != nil {
			t.Fatal(err)
		}
	})
	if err := o.b.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	n, err := o.b.RevokeDeviceFromUI(context.Background(), full.Dev, "test", o.prompt("pw-pw-pw-pw-pw-pw", o.paper))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := o.b.unlockedSession()
	if n != 1 || o.asked.Load() != 1 || s.st.Epoch() != 2 || !s.st.Members().Devices[full.Dev].Revoked {
		t.Fatalf("revoke key holder: n=%d asked=%d epoch=%d", n, o.asked.Load(), s.st.Epoch())
	}
}
