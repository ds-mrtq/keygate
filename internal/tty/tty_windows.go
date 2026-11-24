//go:build windows

package tty

import (
	"os"

	"golang.org/x/sys/windows"
)

func isTerminal(f *os.File) bool {
	var m uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &m) == nil
}

// disableEcho turns console echo off and returns the function that restores the mode.
func disableEcho(f *os.File) (func(), error) {
	h := windows.Handle(f.Fd())
	var old uint32
	if err := windows.GetConsoleMode(h, &old); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(h, old&^windows.ENABLE_ECHO_INPUT); err != nil {
		return nil, err
	}
	return func() { windows.SetConsoleMode(h, old) }, nil
}

func openControllingTerminal() (*os.File, error) { return nil, ErrNoTerminal }
