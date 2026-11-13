// Package pshell holds the Windows PowerShell plumbing shared by Windows Hello and the GUI dialogs.
package pshell

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"unicode/utf16"
)

// System returns the absolute Windows PowerShell path and a minimal environment whose
// PSModulePath holds only the system module directory (no user-scope module can shadow cmdlets).
func System() (string, []string) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("windir")
	}
	if root == "" {
		root = `C:\Windows`
	}
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = filepath.VolumeName(root)
	}
	dir := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0")
	// SystemDrive: without it the shell expands %SystemDrive%\ProgramData literally and leaves
	// a "%SystemDrive%" cache folder in the working directory.
	return filepath.Join(dir, "powershell.exe"), []string{
		"SystemRoot=" + root, "windir=" + root, "SystemDrive=" + drive,
		"PSModulePath=" + filepath.Join(dir, "Modules"),
		"PATH=" + filepath.Join(root, "System32") + ";" + root,
	}
}

// Encode returns the -EncodedCommand argument (base64 of UTF-16LE).
func Encode(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}
