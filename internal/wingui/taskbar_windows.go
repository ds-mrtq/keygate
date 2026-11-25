//go:build windows

package wingui

import (
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The dialogs run in powershell.exe, so the taskbar would group them under PowerShell's button and
// icon. Giving each dialog window its own AppUserModelID (no shortcut carries it) makes the taskbar
// show a separate KeyGate button with the window's icon (the kg/kgw logo the form already sets).

// appID is the AppUserModelID of every KeyGate dialog window.
const appID = "KeyGate.Broker"

var syscallN = syscall.SyscallN

var (
	procSHGetPropertyStoreForWindow = shell32.NewProc("SHGetPropertyStoreForWindow")
	procFindWindowEx                = user32.NewProc("FindWindowExW")
	procGetWindowThreadProcessId    = user32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible             = user32.NewProc("IsWindowVisible")

	iidPropertyStore = windows.GUID{Data1: 0x886d8eeb, Data2: 0x8cf2, Data3: 0x4446, Data4: [8]byte{0x8d, 0x02, 0xcd, 0xba, 0x1d, 0xbd, 0xcf, 0x99}}
)

// propertyKey is PROPERTYKEY; pkeyAppUserModelID = {9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}, 5.
type propertyKey struct {
	fmtid windows.GUID
	pid   uint32
}

var pkeyAppUserModelID = propertyKey{windows.GUID{Data1: 0x9f4c2855, Data2: 0x9f79, Data3: 0x4b39, Data4: [8]byte{0xa8, 0xd0, 0xe1, 0xd4, 0x2d, 0xe1, 0xd5, 0xf3}}, 5}

// propVariant is PROPVARIANT (24 bytes on x64) holding a VT_LPWSTR.
type propVariant struct {
	vt         uint16
	r1, r2, r3 uint16
	val        uintptr
	_          uintptr
}

const vtLPWSTR = 31

// brandWindows gives every visible top-level window of process pid the KeyGate AppUserModelID,
// polling until done is closed (a dialog may open further windows, e.g. a MessageBox).
func brandWindows(pid uint32, done <-chan struct{}) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err == nil {
		defer windows.CoUninitialize()
	}
	id, _ := windows.UTF16PtrFromString(appID)
	seen := map[uintptr]bool{}
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	for {
		var hw uintptr
		for {
			hw, _, _ = procFindWindowEx.Call(0, hw, 0, 0)
			if hw == 0 {
				break
			}
			if seen[hw] {
				continue
			}
			var p uint32
			procGetWindowThreadProcessId.Call(hw, uintptr(unsafe.Pointer(&p)))
			if p != pid {
				continue
			}
			if v, _, _ := procIsWindowVisible.Call(hw); v == 0 {
				continue
			}
			seen[hw] = true
			setAppID(hw, id)
		}
		select {
		case <-done:
			return
		case <-tick.C:
		}
	}
}

// setAppID sets PKEY_AppUserModel_ID on one window through its property store.
func setAppID(hwnd uintptr, id *uint16) {
	var store *struct{ vtbl *[8]uintptr } // IPropertyStore: IUnknown(3) + GetCount, GetAt, GetValue, SetValue, Commit
	if hr, _, _ := procSHGetPropertyStoreForWindow.Call(hwnd, uintptr(unsafe.Pointer(&iidPropertyStore)), uintptr(unsafe.Pointer(&store))); hr != 0 || store == nil {
		return
	}
	v := propVariant{vt: vtLPWSTR, val: uintptr(unsafe.Pointer(id))}
	self := uintptr(unsafe.Pointer(store))
	if hr, _, _ := syscallN(store.vtbl[6], self, uintptr(unsafe.Pointer(&pkeyAppUserModelID)), uintptr(unsafe.Pointer(&v))); hr == 0 {
		syscallN(store.vtbl[7], self)
	}
	syscallN(store.vtbl[2], self) // Release
}
