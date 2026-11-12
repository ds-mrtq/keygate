//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"

	"keygate/internal/broker"
	"keygate/internal/members"
	"keygate/internal/store"
	"keygate/internal/wingui"
)

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

// cmdTray runs the broker with a notification-area icon instead of a terminal (kgw.exe tray).
func (a *app) cmdTray(args []string) error {
	fs := newFS("tray", a.errw)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	logf, err := openTrayLog(a.home)
	if err != nil {
		return err
	}
	defer logf.Close()
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
	h := wingui.TrayHandlers{
		State:        b.UIState,
		StartSession: func() { report(b.StartSession(ctx, "tray")) },
		EndSession:   func() { b.EndSession("tray") },
		Lock:         b.Lock,
		AddSecret: func() {
			report(func() error {
				r, err := wingui.AddSecretMeta(ctx)
				if err != nil {
					return err
				}
				v, err := wingui.Secret(ctx, "Giá trị cho "+r.Name)
				if err != nil {
					return err
				}
				return b.SetFromUI(ctx, r, v)
			}())
		},
		ApprovePending: func() { report(b.ApprovePendingLocal(ctx)) },
		Devices: func() {
			report(a.trayDevices(ctx, b, logf, func(text string) {
				if t := tray.Load(); t != nil {
					t.Balloon("KeyGate", text)
				}
			}))
		},
		OpenLog: func() { report(wingui.OpenFile(filepath.Join(a.home, trayLogName))) },
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
	u, err := pairURL(a.home)
	if err != nil {
		return err
	}
	pair, err := wingui.Pair(ctx, u, "Quét mã QR bằng Camera của iPhone, hoặc mở liên kết bằng Safari:\r\n\r\n"+u+"\r\n\r\n"+
		"1. Trong Safari: Chia sẻ → Thêm vào Màn hình chính.\r\n"+
		"2. Mở KeyGate từ màn hình chính, dán liên kết, bấm Bắt đầu.\r\n"+
		"3. Gõ mã ghép điện thoại hiện vào ô bên dưới, bấm Tiếp, so 6 từ, rồi nhập mật khẩu chủ và khóa giấy.")
	if err != nil || pair == "" {
		return err
	}
	code, origin, err := b.FetchPairCode(ctx, pair)
	if err != nil {
		return fmt.Errorf("lấy mã đăng ký theo mã ghép %s: %w", pair, err)
	}
	// The relay consumed the pairing code: from here on, any failure or cancel must tell the user
	// to restart pairing on the phone (it keeps waiting on the old code otherwise).
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
			"Vai trò: duyệt (không nhận khóa vault; chỉ duyệt yêu cầu và gửi lệnh).", store.RequestWords(code)); err != nil {
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
		msg := "Chưa thêm thiết bị (" + why + "). Mã ghép đã dùng: trên điện thoại bấm \"Hủy và ghép lại\" để lấy mã mới."
		fmt.Fprintf(logf, "[tray] %s\n", msg)
		balloon(msg)
		return nil
	}
	return done(fmt.Sprintf("Đã thêm %s (%s), vai trò %s.", body.Label, body.Dev, store.RoleText(body.Role)), err)
}
