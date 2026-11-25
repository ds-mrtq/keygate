//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"keygate/internal/approve"
	"keygate/internal/broker"
	"keygate/internal/channel"
	"keygate/internal/members"
	"keygate/internal/store"
	"keygate/internal/transport/relay"
	"keygate/internal/wingui"
)

var procGetConsoleWindow = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow")

// defaultCommand is "tray" when the process has neither a console nor a stderr handle: kgw.exe
// (built -H=windowsgui) started from Explorer, where usage would go nowhere. kg.exe run by a
// program without a console still has its stderr pipe, so it keeps printing usage.
func defaultCommand() string {
	if h, _, _ := procGetConsoleWindow.Call(); h != 0 {
		return ""
	}
	if h, err := syscall.GetStdHandle(syscall.STD_ERROR_HANDLE); err == nil && h != 0 && h != syscall.InvalidHandle {
		return ""
	}
	return "tray"
}

const trayLogName = "broker.log"
const trayLogMax = 1 << 20

// openTrayLog opens KG_HOME/broker.log for append (0600); a log above 1 MiB becomes broker.log.1.
func openTrayLog(home string) (*os.File, error) {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(home, trayLogName)
	if fi, err := os.Stat(p); err == nil && fi.Size() > trayLogMax {
		os.Remove(p + ".1")
		if err := os.Rename(p, p+".1"); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
}

// tsWriter stamps every entry of broker.log with the local time (wingui.LogTimeLayout). Each Write
// is one entry; lines after the first in a Write stay unstamped and continue that entry.
type tsWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (t *tsWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, err := io.WriteString(t.w, time.Now().Format(wingui.LogTimeLayout)+" "); err != nil {
		return 0, err
	}
	return t.w.Write(p)
}

// cmdTray runs the broker with a notification-area icon instead of a terminal (kgw.exe tray).
func (a *app) cmdTray(args []string) error {
	fs := newFS("tray", a.errw)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	logFile, err := openTrayLog(a.home)
	if err != nil {
		return err
	}
	defer logFile.Close()
	logf := &tsWriter{w: logFile}
	ctx := a.brokerCtx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := sigCtx(ctx)
	defer stop()

	var tray atomic.Pointer[wingui.Tray]
	prompt := &wingui.Prompter{Log: logf, Locked: broker.ScreenLocked}
	b, err := broker.New(broker.Config{
		Home: a.home, Approver: a.approver, Prompt: prompt,
		IdleLock: 0, LockOnScreenLock: false,
		OnChange: func() {
			if t := tray.Load(); t != nil {
				t.Refresh()
			}
		},
		OnPrompt: func(text string) {
			if t := tray.Load(); t != nil {
				t.Balloon("KeyGate cần Windows Hello", text)
			}
		},
		OnStartupLocked: func(err error) {
			if t := tray.Load(); t != nil {
				t.Balloon("KeyGate chưa mở khóa", err.Error())
			}
		},
	})
	if err != nil {
		return err
	}
	if a.ready != nil {
		b.OnListen(a.ready)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	report := func(err error) {
		if err == nil {
			return
		}
		fmt.Fprintf(logf, "[tray] %v\n", err) // errors carry names and reasons, never secret values
		if !errors.Is(err, wingui.ErrCanceled) {
			if t := tray.Load(); t != nil {
				t.Balloon("KeyGate", err.Error())
			}
		}
	}
	addSecret := func() (string, error) {
		r, err := wingui.AddSecretMeta(ctx)
		if err != nil {
			return "", err
		}
		v, err := wingui.Secret(ctx, "Giá trị cho "+r.Name)
		if err != nil {
			return "", err
		}
		return r.Name, b.SetFromUI(ctx, r, v)
	}
	h := wingui.TrayHandlers{
		State:        b.UIState,
		StartSession: func() { report(b.StartSession(ctx, "tray")) },
		EndSession:   func() { b.EndSession("tray") },
		Lock:         b.Lock,
		AddSecret: func() {
			_, err := addSecret()
			report(err)
		},
		Secrets:        func() { report(traySecrets(ctx, b, logf, addSecret)) },
		ApprovePending: func() { report(b.ApprovePendingLocal(ctx)) },
		Devices: func() {
			report(a.trayDevices(ctx, b, logf, func(text string) {
				if t := tray.Load(); t != nil {
					t.Balloon("KeyGate", text)
				}
			}))
		},
		Policy:  func() { report(trayPolicy(ctx, b, filepath.Join(a.home, "policy.yaml"))) },
		OpenLog: func() { report(wingui.LogWindow(ctx, filepath.Join(a.home, trayLogName))) },
		Quit:    cancel,
	}
	t, err := wingui.RunTray(ctx, h)
	if err != nil {
		return err
	}
	tray.Store(t)
	fmt.Fprintf(logf, "[tray] icon khay sẵn sàng (icon: %s)\n", t.IconPath())
	serveErr := make(chan error, 1)
	go func() { serveErr <- b.Serve(ctx) }()
	select {
	case err := <-serveErr:
		cancel()
		<-t.Done()
		if err != nil {
			fmt.Fprintf(logf, "[tray] broker dừng: %v\n", err)
			wingui.MessageBox("KeyGate", "Broker không chạy được: "+err.Error())
		}
		return err
	case <-t.Done():
		cancel()
		return <-serveErr
	}
}

// trayDevices is the "Thiết bị…" menu: list the vault's devices, then pair a phone or revoke a
// device. The broker does the owner operation on its open store; the master password and the
// paper key only pass through the Win32 dialog wingui.OwnerKeys.
func (a *app) trayDevices(ctx context.Context, b *broker.Broker, logf io.Writer, balloon func(string)) error {
	ms, err := store.ReadMembers(a.home)
	if err != nil {
		return err
	}
	self := b.DeviceID()
	paired, origins := pairedAt(a.home, ms)
	sl, err := b.Seen(ctx)
	seen := seenMap(sl)
	if err != nil {
		fmt.Fprintf(logf, "[tray] không lấy được hoạt động thiết bị từ relay: %v\n", err)
	}
	var rows []wingui.DeviceRow
	for _, d := range sortDevices(store.Devices(ms), self, paired) {
		origin := origins[d.ID].Summary()
		if origin == "" {
			origin = "không rõ"
		}
		last := seenText(seen, d.ID)
		if err != nil {
			last = "không lấy được"
		}
		rows = append(rows, wingui.DeviceRow{Dev: d.ID, Label: d.Label, Role: store.RoleText(d.Role), Paired: pairedText(paired, d.ID),
			Origin: origin, Seen: last, Revoked: d.Revoked, Self: d.ID == self})
	}
	action, dev, err := wingui.Devices(ctx, rows)
	if err != nil {
		return err
	}
	done := func(msg string, err error) error {
		var sw *broker.SyncWarning
		if err != nil && !errors.As(err, &sw) {
			return err
		}
		if sw != nil {
			msg += " Chưa đồng bộ được (" + sw.Err.Error() + "), xem broker.log."
		}
		fmt.Fprintf(logf, "[tray] %s\n", msg)
		balloon(msg)
		return nil
	}
	if action == "revoke" {
		d := ms.Devices[dev]
		n, err := b.RevokeDeviceFromUI(ctx, dev, "thu hồi từ khay", wingui.OwnerKeys)
		msg := fmt.Sprintf("Đã thu hồi %s (%s).", dev, d.Label)
		if d.Role != members.RoleApprover {
			msg = fmt.Sprintf("Đã thu hồi %s (%s), mã hóa lại %d secret.", dev, d.Label, n)
		}
		if n > 0 && d.Role != members.RoleApprover {
			msg += " Thiết bị này từng giữ khóa vault: hãy đổi giá trị ở hệ thống đích (danh sách tên trong broker.log)."
		}
		return done(msg, err)
	}
	pairCode, nonce, u, err := b.OpenPair(ctx)
	if err != nil {
		return err
	}
	// The dialog only waits. A poller fetches the phone's registration and then cancels dctx, which
	// closes the dialog; Hủy closes it first and cancels the poller. 10 minutes = the relay slot TTL.
	dctx, dcancel := context.WithTimeout(ctx, channel.PairTTL)
	defer dcancel()
	type waited struct {
		code   string
		origin relay.Origin
		err    error
	}
	ch := make(chan waited, 1)
	go func() {
		c, o, err := b.WaitPair(dctx, pairCode)
		ch <- waited{c, o, err}
		dcancel()
	}()
	dlgErr := wingui.Pair(dctx, u, "Quét mã QR bằng Camera của iPhone, hoặc mở liên kết bằng Safari:\r\n\r\n"+u+"\r\n\r\n"+
		"1. Trong Safari: Chia sẻ → Thêm vào Màn hình chính.\r\n"+
		"2. Mở KeyGate từ màn hình chính, dán liên kết, bấm Bắt đầu.\r\n"+
		"3. Hộp thoại này tự đóng khi điện thoại gửi xong; sau đó so 6 từ, nhập mật khẩu chủ và khóa giấy.\r\n\r\n"+
		"Mã ghép hết hạn sau 10 phút.")
	dcancel()
	w := <-ch
	if errors.Is(dlgErr, wingui.ErrCanceled) {
		return nil
	}
	if w.err != nil {
		if errors.Is(w.err, context.DeadlineExceeded) {
			w.err = errors.New("mã ghép hết hạn sau 10 phút")
		}
		return fmt.Errorf("chờ điện thoại ghép: %w", w.err)
	}
	code, origin := w.code, w.origin
	// The phone's slot is consumed: from here on, any failure or cancel must tell the user to
	// restart pairing on the phone (it keeps waiting on the old link otherwise).
	var body members.AddBody
	err = func() error {
		if body, err = store.DecodeRequest(code); err != nil {
			return err
		}
		if body.Role != members.RoleApprover {
			return errors.New("mã này là thiết bị đầy đủ; khay chỉ ghép thiết bị duyệt (điện thoại), thiết bị đầy đủ dùng `kg device add`")
		}
		from := origin.Summary()
		if from == "" {
			from = "không rõ"
		}
		if err := wingui.ConfirmDevice(ctx, fmt.Sprintf("Thiết bị mới: %s (%s)\r\nGửi mã từ: %s", body.Label, body.Dev, from),
			"Vai trò: duyệt (không nhận khóa vault; chỉ duyệt yêu cầu và gửi lệnh).", store.PairWords(code, nonce)); err != nil {
			return err
		}
		_, err := b.AddDeviceFromUI(ctx, code, origin, wingui.OwnerKeys)
		return err
	}()
	var sw *broker.SyncWarning
	if err != nil && !errors.As(err, &sw) {
		why := err.Error()
		if errors.Is(err, wingui.ErrCanceled) {
			why = "đã hủy"
		}
		msg := "Chưa thêm thiết bị (" + why + "). Mã ghép đã dùng: trên laptop mở lại \"Ghép điện thoại…\", trên điện thoại bấm \"Hủy và ghép lại\" rồi dùng liên kết mới."
		fmt.Fprintf(logf, "[tray] %s\n", msg)
		balloon(msg)
		return nil
	}
	return done(fmt.Sprintf("Đã thêm %s (%s), vai trò %s.", body.Label, body.Dev, store.RoleText(body.Role)), err)
}

// traySecrets is the "Secret…" menu: the window lists metadata only; Xem giá trị and Xóa go
// through the broker's reveal/delete paths (Windows Hello every time), then the window reopens
// with the result on its status line.
func traySecrets(ctx context.Context, b *broker.Broker, logf io.Writer, addSecret func() (string, error)) error {
	var status, tone, sel string
	for {
		rows, err := b.SecretsForUI(ctx)
		if err != nil {
			return err
		}
		act, err := wingui.Secrets(ctx, rows, status, tone, sel)
		if errors.Is(err, wingui.ErrCanceled) {
			return nil
		}
		if err != nil {
			return err
		}
		status, tone, sel = "", "muted", ""
		var aerr error
		switch act.Action {
		case "add":
			var name string
			name, aerr = addSecret()
			if aerr == nil {
				status, tone, sel = "Đã lưu secret "+approve.Sanitize(name, 200)+".", "add", name
			}
		case "reveal":
			sel = act.Names[0]
			if aerr = b.RevealFromUI(ctx, sel); aerr == nil {
				status, tone = "Đã hiện giá trị của "+approve.Sanitize(sel, 200)+" (cửa sổ giá trị tự đóng sau 60 giây).", "add"
			}
		case "delete":
			var done []string
			done, aerr = b.DeleteFromUI(ctx, act.Names)
			if len(done) > 0 {
				list := approve.Sanitize(strings.Join(done, ", "), 2000)
				fmt.Fprintf(logf, "[tray] Đã xóa %d secret: %s\n", len(done), list)
				status, tone = fmt.Sprintf("Đã xóa %d secret: %s.", len(done), list), "add"
			}
		}
		switch {
		case errors.Is(aerr, wingui.ErrCanceled):
			status, tone = "Đã hủy, không thay đổi gì.", "muted"
		case aerr != nil:
			fmt.Fprintf(logf, "[tray] %s: %v\n", act.Action, aerr)
			status, tone = "Không thực hiện được: "+aerr.Error(), "del"
		}
	}
}

// trayPolicy is the "Policy…" menu: the policy in force, its warnings and what policy.yaml would
// change, read-only; Làm mới re-reads, Mở policy.yaml opens the file (applying stays `kg policy apply`).
func trayPolicy(ctx context.Context, b *broker.Broker, polPath string) error {
	for {
		doc, err := b.PolicyForUI(ctx)
		if err != nil {
			return err
		}
		act, err := wingui.PolicyWindow(ctx, doc)
		if errors.Is(err, wingui.ErrCanceled) {
			return nil
		}
		if err != nil {
			return err
		}
		if act == "open" {
			return wingui.OpenFile(polPath)
		}
	}
}
