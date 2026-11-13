//go:build kgtest

package broker

import "os"

// Test builds only: KG_TEST_SCREEN_LOCKED=1 makes the broker (and the tray prompter, which calls
// ScreenLocked) believe the workstation is locked, so the phone-approval path can be exercised;
// =0 makes it believe the workstation is unlocked (a first local unlock from a locked machine).
func init() {
	switch os.Getenv("KG_TEST_SCREEN_LOCKED") {
	case "1":
		screenLockedProbe = func() bool { return true }
	case "0":
		screenLockedProbe = func() bool { return false }
	}
}
