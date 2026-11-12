//go:build kgtest

package broker

import "os"

// Test builds only: KG_TEST_SCREEN_LOCKED=1 makes the broker (and the tray prompter, which calls
// ScreenLocked) believe the workstation is locked, so the phone-approval path can be exercised.
func init() {
	if os.Getenv("KG_TEST_SCREEN_LOCKED") == "1" {
		screenLockedProbe = func() bool { return true }
	}
}
