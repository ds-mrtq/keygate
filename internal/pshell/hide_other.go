//go:build !windows

package pshell

import "os/exec"

// Hide does nothing outside Windows.
func Hide(*exec.Cmd) {}
