//go:build linux

package execwrap

import "syscall"

// setPdeathsig makes the kernel kill the child if the broker dies.
func setPdeathsig(a *syscall.SysProcAttr) { a.Pdeathsig = syscall.SIGKILL }
