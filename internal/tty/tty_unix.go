//go:build linux || darwin

package tty

import (
	"os"

	"golang.org/x/sys/unix"
)

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	return err == nil
}

// disableEcho turns terminal echo off and returns the function that restores the mode.
func disableEcho(f *os.File) (func(), error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	nt := *old
	nt.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &nt); err != nil {
		return nil, err
	}
	return func() { unix.IoctlSetTermios(fd, ioctlWriteTermios, old) }, nil
}
