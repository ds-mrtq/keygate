package pshell

import (
	"os/exec"
	"syscall"
)

var procGetConsoleWindow = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow")

// Hide keeps a child console window from flashing up when this process has no console of its own
// (kgw.exe, built -H=windowsgui). With a console the command is left untouched.
//
// Only CREATE_NO_WINDOW is set, not HideWindow: STARTF_USESHOWWINDOW with SW_HIDE is applied by
// Windows to the child's first ShowWindow call, which hid the WinForms dialogs of `kgw tray`
// (measured 2026-11-12: form created, never visible).
func Hide(cmd *exec.Cmd) {
	if h, _, _ := procGetConsoleWindow.Call(); h != 0 {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
