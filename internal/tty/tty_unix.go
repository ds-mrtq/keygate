//go:build linux || darwin

package tty

import (
	"context"
	"io"
	"os"
	"strings"

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

func openControllingTerminal() (*os.File, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }

// readTerminalLine reads one line from terminal f, polling so that a cancelled ctx stops the read
// at once and leaves no reader behind to take the next line.
func readTerminalLine(ctx context.Context, f *os.File) (string, error) {
	fd := int(f.Fd())
	var line []byte
	buf := make([]byte, 1)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 100)
		if err == unix.EINTR || n == 0 {
			continue
		}
		if err != nil {
			return "", err
		}
		r, err := unix.Read(fd, buf)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			return "", err
		}
		if r == 0 {
			return "", io.EOF
		}
		if buf[0] == '\n' {
			return strings.TrimRight(string(line), "\r"), nil
		}
		line = append(line, buf[0])
	}
}
