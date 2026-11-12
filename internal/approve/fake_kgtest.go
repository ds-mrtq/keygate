//go:build kgtest

package approve

import (
	"context"
	"os"
)

// Test builds only: KG_TEST_APPROVE=allow|deny replaces the platform user-presence prompt
// with an approver that answers immediately.
func init() {
	platformHook = func() Approver {
		switch os.Getenv("KG_TEST_APPROVE") {
		case "allow":
			return Func(func(context.Context, string) error { return nil })
		case "deny":
			return Func(func(context.Context, string) error { return ErrNotVerified })
		}
		return nil
	}
}
