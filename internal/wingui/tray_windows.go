//go:build windows

package wingui

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"keygate/internal/broker"
	"keygate/internal/icon"
)

var (
	shell32                    = windows.NewLazySystemDLL("shell32.dll")
	gdi32                      = windows.NewLazySystemDLL("gdi32.dll")
	procShellNotifyIcon        = shell32.NewProc("Shell_NotifyIconW")
	procShellExecute           = shell32.NewProc("ShellExecuteW")
	procRegisterClassEx        = user32.NewProc("RegisterClassExW")
	procCreateWindowEx         = user32.NewProc("CreateWindowExW")
	procDefWindowProc          = user32.NewProc("DefWindowProcW")
	procGetMessage             = user32.NewProc("GetMessageW")
	procTranslateMessage       = user32.NewProc("TranslateMessage")
	procDispatchMessage        = user32.NewProc("DispatchMessageW")
	procDestroyWindow          = user32.NewProc("DestroyWindow")
	procPostQuitMessage        = user32.NewProc("PostQuitMessage")
	procRegisterWindowMessage  = user32.NewProc("RegisterWindowMessageW")
	procCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	procAppendMenu             = user32.NewProc("AppendMenuW")
	procTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	procDestroyMenu            = user32.NewProc("DestroyMenu")
	procGetCursorPos           = user32.NewProc("GetCursorPos")
	procSetMenuDefaultItem     = user32.NewProc("SetMenuDefaultItem")
	procFindWindow             = user32.NewProc("FindWindowW")
	procShowWindow             = user32.NewProc("ShowWindow")
	procIsIconic               = user32.NewProc("IsIconic")
	procCreateIconFromResource = user32.NewProc("CreateIconFromResourceEx")
	procCreateIconIndirect     = user32.NewProc("CreateIconIndirect")
	procDestroyIcon            = user32.NewProc("DestroyIcon")
	procCreateBitmap           = gdi32.NewProc("CreateBitmap")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
)

const (
	wmDestroy = 0x0002
	wmNull    = 0x0000
	wmApp     = 0x8000

	wmTrayCallback = wmApp + 1
	wmTrayRefresh  = wmApp + 2
	wmTrayBalloon  = wmApp + 3

	wmLButtonUp = 0x0202
	wmRButtonUp = 0x0205

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2

	nifMessage = 0x1
	nifIcon    = 0x2
	nifTip     = 0x4
	nifInfo    = 0x10

	mfString = 0x0
	mfGrayed = 0x1
	mfSep    = 0x800

	tpmRightButton = 0x2
	tpmReturnCmd   = 0x100

	trayIconSize = 32
)

type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   uintptr
	icon       uintptr
	cursor     uintptr
	background uintptr
	menuName   *uint16
	className  *uint16
	iconSm     uintptr
}

type notifyIconData struct {
	size            uint32
	hwnd            uintptr
	id              uint32
	flags           uint32
	callbackMessage uint32
	icon            uintptr
	tip             [128]uint16
	state           uint32
	stateMask       uint32
	info            [256]uint16
	timeout         uint32
	infoTitle       [64]uint16
	infoFlags       uint32
	guid            [16]byte
	balloonIcon     uintptr
}

type point struct{ x, y int32 }

type msg struct {
	hwnd    uintptr
	message uint32
	wparam  uintptr
	lparam  uintptr
	time    uint32
	pt      point
}

type iconInfo struct {
	isIcon   uint32
	xHotspot uint32
	yHotspot uint32
	mask     uintptr
	color    uintptr
}

// TrayHandlers are the menu actions; each one runs in its own goroutine. A nil ApprovePending
// hides the "Yêu cầu chờ duyệt" entry.
type TrayHandlers struct {
	State                                                                       func() broker.UIState
	StartSession, EndSession, Lock, ApprovePending, AddSecret, Secrets, Devices func()
	Policy, OpenLog, Quit                                                       func()
}

// Tray is the notification-area icon.
type Tray struct {
	h        TrayHandlers
	ctx      context.Context
	hwnd     uintptr
	done     chan struct{}
	mainOpen atomic.Bool // the main window (or a window it opened) is showing

	mu       sync.Mutex
	icons    map[string]uintptr
	iconPath string // "png" or "bgra": which CreateIcon path worked
	balloons *balloonQueue
	taskbar  uint32
}

var (
	trayMu   sync.Mutex
	trayCur  *Tray // the one tray of this process (window procedure has no user data)
	trayProc = windows.NewCallback(trayWndProc)
)

// RunTray creates the icon and runs its message loop on a dedicated OS thread until ctx is
// cancelled or the window is closed. It returns once the icon exists.
func RunTray(ctx context.Context, h TrayHandlers) (*Tray, error) {
	if h.State == nil {
		return nil, errors.New("tray: thiếu State")
	}
	t := &Tray{h: h, ctx: ctx, done: make(chan struct{}), icons: map[string]uintptr{}, balloons: newBalloonQueue(balloonGap, time.Now)}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer close(t.done)
		trayMu.Lock()
		trayCur = t
		trayMu.Unlock()
		hinst, _, _ := procGetModuleHandle.Call(0)
		cls, _ := windows.UTF16PtrFromString("KeyGateTray")
		wc := wndClassEx{size: uint32(unsafe.Sizeof(wndClassEx{})), wndProc: trayProc, instance: hinst, className: cls}
		procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
		title, _ := windows.UTF16PtrFromString("KeyGate")
		hw, _, err := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(title)), 0, 0, 0, 0, 0, 0, 0, hinst, 0)
		if hw == 0 {
			ready <- fmt.Errorf("tạo cửa sổ khay: %v", err)
			return
		}
		t.hwnd = hw
		tb, _ := windows.UTF16PtrFromString("TaskbarCreated")
		r, _, _ := procRegisterWindowMessage.Call(uintptr(unsafe.Pointer(tb)))
		t.taskbar = uint32(r)
		if !t.notify(nimAdd) {
			procDestroyWindow.Call(hw)
			ready <- errors.New("không thêm được icon vào khay hệ thống")
			return
		}
		go func() {
			select {
			case <-ctx.Done():
				procPostMessage.Call(hw, wmClose, 0, 0)
			case <-t.done:
			}
		}()
		ready <- nil
		var m msg
		for {
			r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(r) <= 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
		}
		t.mu.Lock()
		for _, ic := range t.icons {
			procDestroyIcon.Call(ic)
		}
		t.mu.Unlock()
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return t, nil
}

// Done is closed when the message loop ended.
func (t *Tray) Done() <-chan struct{} { return t.done }

// IconPath reports which icon-creation path worked ("png" = CreateIconFromResourceEx, "bgra" = fallback).
func (t *Tray) IconPath() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.iconPath
}

// Refresh re-reads the state and updates icon and tooltip; safe from any goroutine.
func (t *Tray) Refresh() { procPostMessage.Call(t.hwnd, wmTrayRefresh, 0, 0) }

// Balloon shows a notification balloon; safe from any goroutine. Balloons are queued and spaced
// (balloonGap) so one posted right after another is not replaced before it is seen.
func (t *Tray) Balloon(title, text string) {
	if d, sched := t.balloons.add(title, text); sched {
		t.postBalloon(d)
	}
}

func (t *Tray) postBalloon(after time.Duration) {
	if after <= 0 {
		procPostMessage.Call(t.hwnd, wmTrayBalloon, 0, 0)
		return
	}
	time.AfterFunc(after, func() { procPostMessage.Call(t.hwnd, wmTrayBalloon, 0, 0) })
}

func statusText(st broker.UIState) string {
	var s string
	switch {
	case !st.Unlocked:
		s = "KeyGate: đã khóa"
	case !st.Session:
		s = "KeyGate: đã mở, chưa có phiên"
	default:
		s = "KeyGate: phiên làm việc đang mở"
	}
	if st.Pending > 0 {
		s += fmt.Sprintf(", %d yêu cầu chờ duyệt", st.Pending)
	}
	return s
}

func iconState(st broker.UIState) string {
	switch {
	case st.Pending > 0:
		return "pending"
	case !st.Unlocked:
		return "locked"
	case !st.Session:
		return "unlocked"
	}
	return "session"
}

func copyUTF16(dst []uint16, s string) {
	u := utf16.Encode([]rune(s))
	if len(u) > len(dst)-1 {
		u = u[:len(dst)-1]
	}
	copy(dst, u)
	for i := len(u); i < len(dst); i++ {
		dst[i] = 0
	}
}

func (t *Tray) hicon(state string) uintptr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ic, ok := t.icons[state]; ok {
		return ic
	}
	png := icon.PNG(trayIconSize, state)
	ic, _, _ := procCreateIconFromResource.Call(uintptr(unsafe.Pointer(&png[0])), uintptr(len(png)), 1, 0x00030000, trayIconSize, trayIconSize, 0)
	t.iconPath = "png"
	if ic == 0 {
		t.iconPath = "bgra"
		bgra := icon.BGRA(trayIconSize, state)
		color, _, _ := procCreateBitmap.Call(trayIconSize, trayIconSize, 1, 32, uintptr(unsafe.Pointer(&bgra[0])))
		mask, _, _ := procCreateBitmap.Call(trayIconSize, trayIconSize, 1, 1, 0)
		ii := iconInfo{isIcon: 1, mask: mask, color: color}
		ic, _, _ = procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
		procDeleteObject.Call(color)
		procDeleteObject.Call(mask)
	}
	t.icons[state] = ic
	return ic
}

func (t *Tray) notify(op uintptr) bool {
	st := t.h.State()
	nd := notifyIconData{hwnd: t.hwnd, id: 1, flags: nifMessage | nifIcon | nifTip, callbackMessage: wmTrayCallback}
	nd.size = uint32(unsafe.Sizeof(nd))
	nd.icon = t.hicon(iconState(st))
	copyUTF16(nd.tip[:], statusText(st))
	r, _, _ := procShellNotifyIcon.Call(op, uintptr(unsafe.Pointer(&nd)))
	return r != 0
}

func (t *Tray) showBalloon() {
	item, ok, delay, more := t.balloons.next()
	if !ok {
		return
	}
	nd := notifyIconData{hwnd: t.hwnd, id: 1, flags: nifInfo, infoFlags: 1}
	nd.size = uint32(unsafe.Sizeof(nd))
	copyUTF16(nd.infoTitle[:], truncRunes(item[0], 60))
	copyUTF16(nd.info[:], truncRunes(item[1], 200))
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&nd)))
	if more {
		t.postBalloon(delay)
	}
}

const (
	cmdPending = 2 + iota
	cmdStart
	cmdEnd
	cmdLock
	cmdAdd
	cmdSecrets
	cmdDevices
	cmdLog
	cmdQuit
	cmdMain
	cmdPolicy
)

// OpenMain shows the main window and runs the action picked there synchronously (the window it
// opens replaces it), then shows it again, until the user closes it or quits. A second call while
// it runs only brings the main window forward.
func (t *Tray) OpenMain() {
	if !t.mainOpen.CompareAndSwap(false, true) {
		title, _ := windows.UTF16PtrFromString(MainTitle)
		if hw, _, _ := procFindWindow.Call(0, uintptr(unsafe.Pointer(title))); hw != 0 {
			if ic, _, _ := procIsIconic.Call(hw); ic != 0 {
				procShowWindow.Call(hw, 9) // SW_RESTORE
			}
			procSetForegroundWindow.Call(hw)
		}
		return
	}
	defer t.mainOpen.Store(false)
	for {
		act, err := MainWindow(t.ctx, t.h.State(), t.h.ApprovePending != nil)
		if err != nil {
			if !errors.Is(err, ErrCanceled) && t.ctx.Err() == nil {
				t.Balloon("KeyGate", err.Error())
			}
			return
		}
		f := map[string]func(){"start": t.h.StartSession, "end": t.h.EndSession, "lock": t.h.Lock,
			"pending": t.h.ApprovePending, "secrets": t.h.Secrets, "add": t.h.AddSecret,
			"devices": t.h.Devices, "policy": t.h.Policy, "log": t.h.OpenLog, "quit": t.h.Quit}[act]
		if f != nil {
			f()
		}
		if act == "quit" || t.ctx.Err() != nil {
			return
		}
	}
}

func (t *Tray) showMenu() {
	st := t.h.State()
	menu, _, _ := procCreatePopupMenu.Call()
	defer procDestroyMenu.Call(menu)
	add := func(flags, id uintptr, text string) {
		p, _ := windows.UTF16PtrFromString(text)
		procAppendMenu.Call(menu, flags, id, uintptr(unsafe.Pointer(p)))
	}
	add(mfString|mfGrayed, 1, statusText(st))
	add(mfString, cmdMain, "Mở cửa sổ KeyGate…")
	procSetMenuDefaultItem.Call(menu, cmdMain, 0)
	if st.Pending > 0 && t.h.ApprovePending != nil {
		add(mfString, cmdPending, fmt.Sprintf("Yêu cầu chờ duyệt (%d)…", st.Pending))
	}
	if !st.Unlocked || !st.Session {
		add(mfString, cmdStart, "Mở khóa + mở phiên làm việc")
	}
	if st.Session {
		add(mfString, cmdEnd, "Kết thúc phiên")
	}
	if st.Unlocked {
		add(mfString, cmdLock, "Khóa")
	}
	add(mfSep, 0, "")
	add(mfString, cmdSecrets, "Secret…")
	add(mfString, cmdAdd, "Thêm secret…")
	add(mfString, cmdDevices, "Thiết bị…")
	add(mfString, cmdPolicy, "Policy…")
	add(mfString, cmdLog, "Nhật ký broker")
	add(mfSep, 0, "")
	add(mfString, cmdQuit, "Thoát")
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(t.hwnd)
	id, _, _ := procTrackPopupMenu.Call(menu, tpmReturnCmd|tpmRightButton, uintptr(pt.x), uintptr(pt.y), 0, t.hwnd, 0)
	procPostMessage.Call(t.hwnd, wmNull, 0, 0)
	var f func()
	switch id {
	case cmdPending:
		f = t.h.ApprovePending
	case cmdStart:
		f = t.h.StartSession
	case cmdEnd:
		f = t.h.EndSession
	case cmdLock:
		f = t.h.Lock
	case cmdAdd:
		f = t.h.AddSecret
	case cmdSecrets:
		f = t.h.Secrets
	case cmdDevices:
		f = t.h.Devices
	case cmdPolicy:
		f = t.h.Policy
	case cmdLog:
		f = t.h.OpenLog
	case cmdQuit:
		f = t.h.Quit
	case cmdMain:
		f = t.OpenMain
	}
	if f != nil {
		go f()
	}
}

func trayWndProc(hwnd, m, wparam, lparam uintptr) uintptr {
	trayMu.Lock()
	t := trayCur
	trayMu.Unlock()
	if t != nil {
		switch {
		case m == wmTrayCallback:
			switch lparam & 0xFFFF {
			case wmLButtonUp:
				go t.OpenMain()
			case wmRButtonUp:
				t.showMenu()
			}
			return 0
		case m == wmTrayRefresh:
			t.notify(nimModify)
			return 0
		case m == wmTrayBalloon:
			t.showBalloon()
			return 0
		case t.taskbar != 0 && uint32(m) == t.taskbar:
			t.notify(nimAdd)
			return 0
		case m == wmClose:
			procDestroyWindow.Call(hwnd)
			return 0
		case m == wmDestroy:
			nd := notifyIconData{hwnd: hwnd, id: 1}
			nd.size = uint32(unsafe.Sizeof(nd))
			procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&nd)))
			procPostQuitMessage.Call(0)
			return 0
		}
	}
	r, _, _ := procDefWindowProc.Call(hwnd, m, wparam, lparam)
	return r
}

// OpenFile opens path with its default program (ShellExecute "open").
func OpenFile(path string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, _ := procShellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(p)), 0, 0, 1)
	if r <= 32 {
		return fmt.Errorf("không mở được %s (mã %d)", path, r)
	}
	return nil
}
