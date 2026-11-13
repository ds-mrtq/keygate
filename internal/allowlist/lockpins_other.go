//go:build !windows

package allowlist

import (
	"os"
	"syscall"
)

// openLocked opens path read-only without following a final symlink. There is no mandatory
// locking here: this only narrows the window, it does not close it.
func openLocked(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
