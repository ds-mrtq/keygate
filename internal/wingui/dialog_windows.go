//go:build windows

package wingui

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                     = windows.NewLazySystemDLL("user32.dll")
	procDialogBoxIndirectParam = user32.NewProc("DialogBoxIndirectParamW")
	procEndDialog              = user32.NewProc("EndDialog")
	procGetDlgItemText         = user32.NewProc("GetDlgItemTextW")
	procSetDlgItemText         = user32.NewProc("SetDlgItemTextW")
	procSendDlgItemMessage     = user32.NewProc("SendDlgItemMessageW")
	procSetWindowPos           = user32.NewProc("SetWindowPos")
	procSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	procSwitchToThisWindow     = user32.NewProc("SwitchToThisWindow")
	procPostMessage            = user32.NewProc("PostMessageW")
	procSetTimer               = user32.NewProc("SetTimer")
	procKillTimer              = user32.NewProc("KillTimer")
	procMessageBox             = user32.NewProc("MessageBoxW")
	procGetModuleHandle        = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW")
	procLoadImage              = user32.NewProc("LoadImageW")
	procSendMessage            = user32.NewProc("SendMessageW")
)

// Window messages, styles and ids used by the in-memory dialog templates.
const (
	wmInitDialog = 0x0110
	wmCommand    = 0x0111
	wmClose      = 0x0010
	wmTimer      = 0x0113

	idOK     = 1
	idCancel = 2

	idText = 1000
	idEdit = 1001

	emSetLimitText = 0x00C5

	wsPopup       = 0x80000000
	wsChild       = 0x40000000
	wsVisible     = 0x10000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsTabStop     = 0x00010000
	wsBorder      = 0x00800000
	wsVScroll     = 0x00200000
	dsModalFrame  = 0x80
	dsSetFont     = 0x40
	dsCenter      = 0x0800
	wsExTopmost   = 0x00000008
	wsExAppWindow = 0x00040000
	esMultiline   = 0x0004
	esPassword    = 0x0020
	esAutoVScrl   = 0x0040
	esAutoHScrl   = 0x0080
	esReadOnly    = 0x0800
	bsPush        = 0x0
	bsDefPush     = 0x1

	classButton = 0x0080
	classEdit   = 0x0081
	classStatic = 0x0082

	showSecretTimeout = 60 * time.Second
	timerID           = 1
)

type dlgItem struct {
	class      uint16
	style      uint32
	x, y, w, h int16
	id         uint16
	text       string
}

// buildTemplate lays out a DLGTEMPLATE followed by its DLGITEMTEMPLATEs (dialog units, Segoe UI 9).
func buildTemplate(title string, w, h int16, items []dlgItem) unsafe.Pointer {
	var b bytes.Buffer
	le := binary.LittleEndian
	put := func(v any) { binary.Write(&b, le, v) }
	z := func(s string) {
		for _, c := range utf16.Encode([]rune(s)) {
			put(c)
		}
		put(uint16(0))
	}
	align4 := func() {
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	put(uint32(wsPopup | wsCaption | wsSysMenu | wsVisible | dsModalFrame | dsSetFont | dsCenter))
	put(uint32(wsExTopmost | wsExAppWindow)) // topmost from creation; taskbar button so it can be found
	put(uint16(len(items)))
	put(int16(0))
	put(int16(0))
	put(w)
	put(h)
	put(uint16(0)) // no menu
	put(uint16(0)) // default dialog class
	z(title)
	put(uint16(9))
	z("Segoe UI")
	for _, it := range items {
		align4()
		put(it.style | wsChild | wsVisible)
		put(uint32(0))
		put(it.x)
		put(it.y)
		put(it.w)
		put(it.h)
		put(it.id)
		put(uint16(0xFFFF))
		put(it.class)
		z(it.text)
		put(uint16(0)) // no creation data
	}
	// the template must start on a DWORD boundary: copy into uint32-backed memory
	mem := make([]uint32, (b.Len()+3)/4)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&mem[0])), len(mem)*4), b.Bytes())
	keep = append(keep[:0], mem) // keep alive until the next dialog (DialogBox is synchronous anyway)
	return unsafe.Pointer(&mem[0])
}

var keep [][]uint32

type dlgState struct {
	ctx      context.Context
	finished chan struct{}
	onInit   func(hwnd uintptr)
	onOK     func(hwnd uintptr) // reads fields before the dialog is destroyed
	timeout  time.Duration
	deadline time.Time // set at WM_INITDIALOG when timeout > 0
}

var (
	dlgMu sync.Mutex // one dialog at a time
	cur   *dlgState  // the running dialog (guarded by dlgMu)
	dlgCB = windows.NewCallback(dlgProc)
)

func dlgProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	st := cur
	switch msg {
	case wmInitDialog:
		procSetWindowPos.Call(hwnd, ^uintptr(0), 0, 0, 0, 0, 0x0001|0x0002|0x0040) // HWND_TOPMOST, NOMOVE|NOSIZE|SHOWWINDOW
		procSetForegroundWindow.Call(hwnd)
		procSwitchToThisWindow.Call(hwnd, 1)
		setAppIcon(hwnd)
		if st.onInit != nil {
			st.onInit(hwnd)
		}
		if st.timeout > 0 {
			st.deadline = time.Now().Add(st.timeout)
			setText(hwnd, idText, countdownText(st.timeout))
			procSetTimer.Call(hwnd, timerID, 1000, 0) // tick each second to update the countdown
		}
		go func() {
			select {
			case <-st.ctx.Done():
				procPostMessage.Call(hwnd, wmClose, 0, 0)
			case <-st.finished:
			}
		}()
		return 1
	case wmCommand:
		switch id := wparam & 0xFFFF; id {
		case idOK:
			if st.onOK != nil {
				st.onOK(hwnd)
			}
			procEndDialog.Call(hwnd, idOK)
			return 1
		case idCancel:
			procEndDialog.Call(hwnd, idCancel)
			return 1
		}
	case wmTimer:
		if wparam == timerID {
			left := time.Until(st.deadline)
			if left <= 0 {
				procKillTimer.Call(hwnd, timerID)
				procEndDialog.Call(hwnd, idCancel)
				return 1
			}
			setText(hwnd, idText, countdownText(left))
			return 1
		}
	case wmClose:
		procEndDialog.Call(hwnd, idCancel)
		return 1
	}
	return 0
}

// setAppIcon puts the exe's logo (group icon 1, from cmd/kg/rsrc_windows_amd64.syso) on the title
// bar and taskbar button; without the resource LoadImage fails and Windows keeps its default.
func setAppIcon(hwnd uintptr) {
	const imageIcon, lrShared, wmSetIcon = 1, 0x8000, 0x0080
	hinst, _, _ := procGetModuleHandle.Call(0)
	for _, ic := range [][2]uintptr{{0, 16}, {1, 32}} { // ICON_SMALL, ICON_BIG
		if h, _, _ := procLoadImage.Call(hinst, 1, imageIcon, ic[1], ic[1], lrShared); h != 0 {
			procSendMessage.Call(hwnd, wmSetIcon, ic[0], h)
		}
	}
}

// countdownText renders the auto-close line, rounding up so it never shows "0 giây" while open.
func countdownText(left time.Duration) string {
	return fmt.Sprintf("Tự đóng sau %d giây.", int((left+time.Second-1)/time.Second))
}

// runDialog shows tmpl modally on its own locked OS thread and returns the button id.
func runDialog(ctx context.Context, tmpl unsafe.Pointer, st *dlgState) (int, error) {
	dlgMu.Lock()
	defer dlgMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	st.ctx, st.finished = ctx, make(chan struct{})
	defer close(st.finished)
	hinst, _, _ := procGetModuleHandle.Call(0)
	res := make(chan int, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies with the goroutine
		cur = st
		r, _, _ := procDialogBoxIndirectParam.Call(hinst, uintptr(tmpl), 0, dlgCB, 0)
		res <- int(int32(r))
	}()
	r := <-res
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if r == -1 || r == 0 {
		return 0, errors.New("không mở được hộp thoại")
	}
	return r, nil
}

func setText(hwnd uintptr, id int, s string) {
	p, _ := windows.UTF16PtrFromString(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n"))
	procSetDlgItemText.Call(hwnd, uintptr(id), uintptr(unsafe.Pointer(p)))
}

// Secret shows a modal hidden-input dialog and returns the typed value. The UTF-16 buffer that held
// it is zeroed. Cancel returns ErrCanceled.
func Secret(ctx context.Context, prompt string) (string, error) {
	const maxChars = 32767 // 64 KiB of UTF-16
	var value string
	st := &dlgState{
		onInit: func(hwnd uintptr) {
			procSendDlgItemMessage.Call(hwnd, idEdit, emSetLimitText, maxChars, 0)
		},
		onOK: func(hwnd uintptr) { value = readEdit(hwnd, idEdit, maxChars) },
	}
	tmpl := buildTemplate("KeyGate", 230, 92, []dlgItem{
		{classStatic, 0, 8, 8, 214, 28, idText, truncRunes(prompt, 220)},
		{classEdit, wsBorder | wsTabStop | esPassword | esAutoHScrl, 8, 42, 214, 14, idEdit, ""},
		{classButton, wsTabStop | bsDefPush, 118, 70, 50, 14, idOK, "OK"},
		{classButton, wsTabStop | bsPush, 172, 70, 50, 14, idCancel, "Hủy"},
	})
	r, err := runDialog(ctx, tmpl, st)
	if err != nil {
		return "", err
	}
	if r != idOK {
		return "", ErrCanceled
	}
	return value, nil
}

// readEdit returns the text of edit control id and zeroes the UTF-16 buffer that held it.
func readEdit(hwnd uintptr, id, maxChars int) string {
	buf := make([]uint16, maxChars+1)
	n, _, _ := procGetDlgItemText.Call(hwnd, uintptr(id), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	r := utf16.Decode(buf[:n])
	v := string(r)
	clear(buf)
	clear(r)
	return v
}

// OwnerKeys asks for the master password and the paper key in one modal Win32 dialog (both
// hidden). They never pass through PowerShell. hint (why the previous try failed) replaces the
// intro line when set. Cancel returns ErrCanceled. Go strings cannot be wiped: callers use them
// once and drop them.
func OwnerKeys(ctx context.Context, hint string) (password, paperKey string, err error) {
	intro := "Nhập mật khẩu chủ và khóa giấy để ký thay đổi thiết bị của vault. KeyGate không lưu lại hai giá trị này."
	if hint != "" {
		intro = truncRunes(hint, 160)
	}
	const (
		idPaper            = 1002
		maxPwd, maxPaper   = 1024, 256
		idLblPwd, idLblKey = 1003, 1004
	)
	st := &dlgState{
		onInit: func(hwnd uintptr) {
			procSendDlgItemMessage.Call(hwnd, idEdit, emSetLimitText, maxPwd, 0)
			procSendDlgItemMessage.Call(hwnd, idPaper, emSetLimitText, maxPaper, 0)
		},
		onOK: func(hwnd uintptr) {
			password = readEdit(hwnd, idEdit, maxPwd)
			paperKey = readEdit(hwnd, idPaper, maxPaper)
		},
	}
	tmpl := buildTemplate("KeyGate: thao tác chủ vault", 250, 134, []dlgItem{
		{classStatic, 0, 8, 8, 234, 18, idText, intro},
		{classStatic, 0, 8, 32, 234, 10, idLblPwd, "Mật khẩu chủ"},
		{classEdit, wsBorder | wsTabStop | esPassword | esAutoHScrl, 8, 43, 234, 14, idEdit, ""},
		{classStatic, 0, 8, 64, 234, 10, idLblKey, "Khóa giấy"},
		{classEdit, wsBorder | wsTabStop | esPassword | esAutoHScrl, 8, 75, 234, 14, idPaper, ""},
		{classButton, wsTabStop | bsDefPush, 138, 112, 50, 14, idOK, "OK"},
		{classButton, wsTabStop | bsPush, 192, 112, 50, 14, idCancel, "Hủy"},
	})
	r, err := runDialog(ctx, tmpl, st)
	if err != nil {
		return "", "", err
	}
	if r != idOK {
		return "", "", ErrCanceled
	}
	if password == "" || paperKey == "" {
		return "", "", errors.New("cần nhập cả mật khẩu chủ và khóa giấy")
	}
	return password, paperKey, nil
}

// ShowSecret shows a value in a read-only box that closes itself after 60 seconds.
func ShowSecret(ctx context.Context, name, value string) error {
	st := &dlgState{
		onInit:  func(hwnd uintptr) { setText(hwnd, idEdit, value) },
		timeout: showSecretTimeout,
	}
	tmpl := buildTemplate("KeyGate: "+truncRunes(name, 100), 260, 122, []dlgItem{
		{classEdit, wsBorder | wsVScroll | wsTabStop | esMultiline | esReadOnly | esAutoVScrl, 8, 8, 244, 70, idEdit, ""},
		{classStatic, 0, 8, 88, 150, 10, idText, "Tự đóng sau 60 giây."},
		{classButton, wsTabStop | bsDefPush, 202, 100, 50, 14, idOK, "Đóng"},
	})
	_, err := runDialog(ctx, tmpl, st)
	return err
}

// MessageBox shows a blocking error box (used when the tray cannot start).
func MessageBox(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10|0x40000|0x10000) // ICONERROR|TOPMOST|SETFOREGROUND
}
