//go:build windows

package broker

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	procOpenInputDsk = user32.NewProc("OpenInputDesktop")
	procCloseDesktop = user32.NewProc("CloseDesktop")

	wtsapi32     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuery = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFree  = wtsapi32.NewProc("WTSFreeMemory")
)

const (
	desktopSwitchDesktop = 0x0100
	wtsSessionInfoEx     = 25 // WTS_INFO_CLASS WTSSessionInfoEx
	wtsSessionStateLock  = 0  // WTS_SESSIONSTATE_LOCK (Windows 8+; Win7 had the values swapped)
)

// wtsInfoEx mirrors WTSINFOEXW with its WTSINFOEX_LEVEL1_W prefix: the union is 8-byte aligned
// (LARGE_INTEGER members), so SessionFlags sits at byte offset 16.
type wtsInfoEx struct {
	Level        uint32
	_            uint32
	SessionID    uint32
	SessionState int32
	SessionFlags int32
}

// osScreenLocked reports whether this logon session is locked (Win+L). The Windows 10/11 lock
// screen runs on the Default desktop, so OpenInputDesktop keeps succeeding while locked (measured
// 2026-11-12); the session flag from WTSQuerySessionInformation is used instead, with the desktop
// probe only as fallback when the query fails.
func osScreenLocked() bool {
	var sid uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid) == nil {
		var info *wtsInfoEx
		var n uint32
		r, _, _ := procWTSQuery.Call(0, uintptr(sid), wtsSessionInfoEx, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&n)))
		if r != 0 && info != nil {
			defer procWTSFree.Call(uintptr(unsafe.Pointer(info)))
			if n >= uint32(unsafe.Sizeof(wtsInfoEx{})) && info.Level == 1 {
				return info.SessionFlags == wtsSessionStateLock
			}
		}
	}
	h, _, _ := procOpenInputDsk.Call(0, 0, desktopSwitchDesktop)
	if h == 0 {
		return true
	}
	procCloseDesktop.Call(h)
	return false
}
