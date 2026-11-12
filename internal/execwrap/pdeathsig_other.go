//go:build !windows && !linux

package execwrap

import "syscall"

func setPdeathsig(*syscall.SysProcAttr) {}
