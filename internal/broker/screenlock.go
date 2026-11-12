package broker

// screenLockedProbe reports whether the interactive desktop is locked; a kgtest build can override it.
var screenLockedProbe = osScreenLocked

// ScreenLocked reports whether the interactive desktop is locked (Windows OpenInputDesktop probe;
// always false elsewhere).
func ScreenLocked() bool { return screenLockedProbe() }
