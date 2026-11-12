//go:build !windows

package dir

import "syscall"

// noFollow makes open fail on a symlink final path component.
const noFollow = syscall.O_NOFOLLOW
