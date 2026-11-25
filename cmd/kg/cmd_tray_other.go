//go:build !windows

package main

import "errors"

func (a *app) cmdTray(args []string) error {
	return errors.New("kg tray chỉ có trên Windows; dùng kg broker")
}

// defaultCommand: without arguments kg prints usage.
func defaultCommand() string { return "" }
