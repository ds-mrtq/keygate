//go:build !windows

package broker

// osScreenLocked: no screen-lock probe outside Windows (idle timeout only).
func osScreenLocked() bool { return false }
