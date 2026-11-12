package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"keygate/internal/allowlist"
	"keygate/internal/api"
	"keygate/internal/broker"
	"keygate/internal/broker/wire"
	"keygate/internal/hook"
	"keygate/internal/mcp"
	"keygate/internal/store"
)

func (a *app) cmdBroker(args []string) error {
	fs := newFS("broker", a.errw)
	idle := fs.Duration("idle", 0, "tự khóa sau thời gian không có thao tác được duyệt (0 = không tự khóa)")
	onScreenLock := fs.Bool("lock-on-screen-lock", false, "khóa vault khi khóa màn hình (ngoài phiên làm việc)")
	wait := fs.Duration("approval-wait", 0, "chờ duyệt tối đa bấy lâu trước khi trả pending, exit 75 (0 = 270s)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	b, err := broker.New(broker.Config{Home: a.home, Approver: a.approver, Prompt: a.brokerPrompt, IdleLock: *idle, LockOnScreenLock: *onScreenLock, ApprovalWait: *wait, ScreenLocked: a.screenLocked})
	if err != nil {
		return err
	}
	ctx := a.brokerCtx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := sigCtx(ctx)
	defer stop()
	if a.ready != nil {
		b.OnListen(a.ready)
	}
	return b.Serve(ctx)
}

// cmdSet sends metadata only. The broker asks for the value (hidden) on ITS OWN terminal, so a
// squatted socket or an agent without a terminal never sees or supplies it.
func (a *app) cmdSet(args []string) error {
	fs := newFS("set", a.errw)
	kind := fs.String("kind", "env", "env|file|oracle-wallet|template")
	env := fs.String("env", "dev", "test|dev|prod|...")
	envName := fs.String("env-name", "", "tên biến môi trường")
	tns := fs.String("tns-alias", "", "alias TNS (oracle-wallet)")
	user := fs.String("user", "", "user (oracle-wallet)")
	ext := fs.String("file-ext", "", "đuôi file (kind=file)")
	desc := fs.String("desc", "", "mô tả")
	tags := fs.String("tags", "", "tag cách nhau bằng dấu phẩy")
	fromFile := fs.String("from-file", "", "broker tự đọc giá trị từ file này (sau khi duyệt người)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("dùng: kg set <tên> [--kind ...] [--env ...]")
	}
	req := api.SetRequest{Name: pos[0], Kind: *kind, Env: *env, Desc: *desc, EnvName: *envName, TNSAlias: *tns, User: *user, FileExt: *ext}
	if *tags != "" {
		req.Tags = strings.Split(*tags, ",")
	}
	args2 := wire.SetArgs{Request: req}
	if *fromFile != "" {
		args2.FromFile = absPath(*fromFile)
	} else {
		fmt.Fprintln(a.errw, "Nhập giá trị trong cửa sổ của broker (nó sẽ hỏi, ẩn).")
	}
	if err := a.client().Set(context.Background(), args2); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Đã lưu %s (kind=%s, env=%s)\n", req.Name, req.Kind, req.Env)
	return nil
}

// cmdImport sends file paths only; the broker reads the file itself after a human approval.
func (a *app) cmdImport(args []string) error {
	fs := newFS("import", a.errw)
	dotenv := fs.String("dotenv", "", "đường dẫn file .env")
	gl := fs.String("gitleaks", "", "báo cáo gitleaks JSON (không có --redact)")
	prefix := fs.String("prefix", "", "tiền tố tên secret, vd llm/")
	env := fs.String("env", "dev", "môi trường gán cho secret")
	rewrite := fs.Bool("rewrite", false, "thay giá trị trong file nguồn bằng ${secret:tên}")
	compare := fs.Bool("compare", false, "chỉ so sánh file .env với vault (same|diff|missing|extra), không ghi")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if (*dotenv == "") == (*gl == "") {
		return errors.New("chọn đúng một nguồn: --dotenv <file> hoặc --gitleaks <report>")
	}
	ia := wire.ImportArgs{Prefix: *prefix, Env: *env, Rewrite: *rewrite}
	if *dotenv != "" {
		ia.Dotenv = absPath(*dotenv)
	} else {
		ia.Gitleaks = absPath(*gl)
	}
	if *compare {
		if *dotenv == "" || *rewrite {
			return errors.New("--compare chỉ dùng với --dotenv và không kèm --rewrite")
		}
		cr, err := a.client().Compare(context.Background(), ia)
		if err != nil {
			return err
		}
		for _, it := range cr.Items {
			fmt.Fprintf(a.out, "%-8s %s\n", it.Status, it.Name)
		}
		for _, n := range cr.Extra {
			fmt.Fprintf(a.out, "%-8s %s\n", "extra", n)
		}
		for _, l := range cr.Unparsed {
			fmt.Fprintf(a.out, "unparsed line %d\n", l)
		}
		return nil
	}
	r, err := a.client().Import(context.Background(), ia)
	if err != nil {
		return err
	}
	if r.Count == 0 {
		fmt.Fprintln(a.out, "Không có gì để nhập.")
		return nil
	}
	fmt.Fprintf(a.out, "Đã nhập %d secret: %s\n", r.Count, strings.Join(r.Names, ", "))
	if *rewrite {
		fmt.Fprintln(a.out, "Đã thay giá trị trong file nguồn bằng ${secret:...}")
	}
	return nil
}

func (a *app) cmdList(args []string) error {
	fs := newFS("list", a.errw)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	l, err := a.client().List(context.Background())
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TÊN\tENV\tKIND\tDÙNG LẦN CUỐI\tGHI CHÚ")
	for _, s := range l {
		last, note := "-", ""
		if s.LastUsed != nil {
			last = s.LastUsed.Local().Format("2006-01-02 15:04")
		}
		if s.Conflict {
			note = "XUNG ĐỘT"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.Name, s.Env, s.Kind, last, note)
	}
	return tw.Flush()
}

// cmdRun implements `kg run` and, with isResolve, `kg resolve <file>`.
func (a *app) cmdRun(args []string, isResolve bool) error {
	flagArgs, argv, found := splitDash(args)
	fs := newFS("run", a.errw)
	var secrets multiFlag
	fs.Var(&secrets, "secret", "tên secret (lặp lại được)")
	as := fs.String("as", "", "env|file|wallet")
	dir := fs.String("dir", "", "thư mục chạy lệnh")
	agent := fs.String("agent", a.agent("cli"), "nhãn người gọi cho audit")
	into := fs.String("into", "", "biến nhận đường dẫn file đã thay (resolve)")
	pos, err := parseArgs(fs, flagArgs)
	if err != nil {
		return err
	}
	if !found || len(argv) == 0 {
		return errors.New("thiếu lệnh: kg run --secret A -- lệnh tham-số…")
	}
	req := api.RunRequest{Secrets: secrets, Argv: argv, As: *as, Dir: *dir, Agent: *agent, Into: *into}
	if req.Dir == "" {
		req.Dir, _ = os.Getwd()
	}
	if isResolve {
		if len(pos) != 1 {
			return errors.New("dùng: kg resolve <file> [--into ENV] -- lệnh…")
		}
		if req.Resolve, err = filepath.Abs(pos[0]); err != nil {
			return err
		}
	} else if len(pos) != 0 {
		return fmt.Errorf("tham số thừa trước --: %v", pos)
	}
	code, err := a.client().Run(context.Background(), req, a.out, a.errw)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCodeErr{code: code}
	}
	return nil
}

func (a *app) cmdGrant(args []string) error {
	flagArgs, argv, found := splitDash(args)
	fs := newFS("grant", a.errw)
	agent := fs.String("agent", a.agent("cli"), "nhãn người gọi")
	pos, err := parseArgs(fs, flagArgs)
	if err != nil {
		return err
	}
	if len(pos) != 1 || !found || len(argv) == 0 {
		return errors.New("dùng: kg grant <secret> -- lệnh…")
	}
	g, err := a.client().RequestGrant(context.Background(), pos[0], argv, *agent)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Đã cấp %s cho mẫu %q (%s) đến %s\n", g.Secret, g.Pattern, g.Approval, g.Expires.Local().Format(time.DateTime))
	return nil
}

func (a *app) cmdReveal(args []string) error {
	fs := newFS("reveal", a.errw)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("dùng: kg reveal <tên>")
	}
	if err := a.client().Reveal(context.Background(), pos[0]); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Giá trị đã được hiển thị trên cửa sổ của broker (không trả về qua socket).")
	return nil
}

func (a *app) cmdStatus(args []string) error {
	sf, err := a.client().StatusFull(context.Background())
	if err != nil {
		return err
	}
	st := sf.Status
	state := "ĐÃ KHÓA"
	if st.Unlocked {
		state = "đã mở"
	}
	lock := "tự khóa: không"
	if st.LockAfter != "" {
		lock = "tự khóa sau " + st.LockAfter
	}
	fmt.Fprintf(a.out, "Broker: %s | thiết bị %s | vault %s | epoch %d | %s\n", state, st.Device, st.Vault, st.Epoch, lock)
	if sf.Session {
		fmt.Fprintf(a.out, "Phiên làm việc: ĐANG MỞ %s từ %s (không tự khóa; grant user-presence/device tự cấp)\n", sf.SessionID, sf.SessionStart.Local().Format(time.DateTime))
	} else {
		fmt.Fprintln(a.out, "Phiên làm việc: không (mỗi grant hỏi duyệt một lần)")
	}
	fmt.Fprintf(a.out, "Policy: %s | xung đột: %d\n", map[bool]string{true: "khớp pin", false: "KHÔNG hợp lệ (mọi grant bị từ chối)"}[st.PolicyOK], st.Conflicts)
	if pin, err := genesisPin(a.home); err == nil {
		fmt.Fprintf(a.out, "Ghim genesis (so với máy khác bằng kênh tin cậy): %s\n", pin)
	}
	fmt.Fprintf(a.out, "Điện thoại duyệt: %d thiết bị | yêu cầu chờ: %d\n", sf.Approvers, sf.Pending)
	if st.LastSyncAt != nil {
		fmt.Fprintf(a.out, "Sync gần nhất: %s\n", st.LastSyncAt.Local().Format(time.DateTime))
	}
	for _, g := range st.Grants {
		exp := "không hết hạn"
		if !g.Expires.IsZero() {
			exp = "hết hạn " + g.Expires.Local().Format(time.DateTime)
		}
		fmt.Fprintf(a.out, "Grant: %s | %s | %s | %s\n", g.Secret, g.Pattern, g.Approval, exp)
	}
	return nil
}

// genesisPin derives the genesis pin from the public files of KG_HOME (no keys, no lock needed).
func genesisPin(home string) (string, error) {
	ms, err := store.ReadMembers(home)
	if err != nil {
		return "", err
	}
	return store.GenesisPinOf(ms.Vault, ms.GenesisHash), nil
}

func (a *app) cmdLock(args []string) error {
	if err := a.client().Lock(context.Background()); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Đã khóa.")
	return nil
}

// cmdGrants lists the remembered grants (`kg grants`) or revokes them (`kg grants revoke <secret>|--all`).
func (a *app) cmdGrants(args []string) error {
	ctx := context.Background()
	if len(args) == 0 {
		l, err := a.client().Grants(ctx)
		if err != nil {
			return err
		}
		if len(l) == 0 {
			fmt.Fprintln(a.out, "Không có grant nào đang nhớ.")
			return nil
		}
		tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SECRET\tMẪU LỆNH\tDUYỆT\tBỞI\tLÚC\tHẾT HẠN\tBỀN")
		for _, g := range l {
			exp := "không hết hạn"
			if g.Expires != nil {
				exp = g.Expires.Local().Format(time.DateTime)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\tby=%s\t%s\t%s\t%v\n", g.Secret, g.Pattern, g.Approval, g.By, g.At.Local().Format(time.DateTime), exp, g.Durable)
		}
		return tw.Flush()
	}
	if args[0] != "revoke" {
		return errors.New("dùng: kg grants | kg grants revoke <secret> | kg grants revoke --all")
	}
	fs := newFS("grants revoke", a.errw)
	all := fs.Bool("all", false, "thu hồi mọi grant")
	pos, err := parseArgs(fs, args[1:])
	if err != nil {
		return err
	}
	if *all == (len(pos) > 0) || len(pos) > 1 {
		return errors.New("dùng: kg grants revoke <secret> | kg grants revoke --all")
	}
	name := ""
	if len(pos) == 1 {
		name = pos[0]
	}
	n, err := a.client().GrantsRevoke(ctx, name, *all)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Đã thu hồi %d grant.\n", n)
	return nil
}

func (a *app) cmdPolicy(args []string) error {
	if len(args) != 1 || args[0] != "apply" {
		return errors.New("dùng: kg policy apply")
	}
	r, err := a.client().PolicyApply(context.Background())
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Đã ghim policy.yaml (%d grant, %s)\n", r.Grants, r.Hash)
	return nil
}

func (a *app) cmdHook(args []string) int {
	if len(args) != 1 || args[0] != "check" {
		fmt.Fprintln(a.errw, "dùng: kg hook check")
		return 2
	}
	in, err := readAllLimited(a.stdin, 4<<20)
	if err == nil {
		var blocked bool
		var reason string
		blocked, reason, err = hook.Check(in, a.home)
		if err == nil {
			if blocked {
				fmt.Fprintln(a.errw, reason)
				return 2
			}
			return 0
		}
	}
	fmt.Fprintln(a.errw, "KeyGate hook: không đọc được đầu vào, chặn theo nguyên tắc hỏng an toàn:", err)
	return 2
}

func (a *app) cmdMCP(args []string) error {
	ctx, stop := sigCtx(context.Background())
	defer stop()
	return mcp.Serve(ctx, a.stdin, a.out, a.client())
}

func (a *app) cmdDelete(args []string) error {
	fs := newFS("delete", a.errw)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return errors.New("dùng: kg delete <tên> [<tên>...]")
	}
	r, err := a.client().Delete(context.Background(), pos)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Đã xóa %d secret: %s\n", len(r.Names), strings.Join(r.Names, ", "))
	return nil
}

func (a *app) cmdSession(args []string) error {
	if len(args) != 1 || (args[0] != "start" && args[0] != "end") {
		return errors.New("dùng: kg session start | kg session end")
	}
	if args[0] == "end" {
		if err := a.client().SessionEnd(context.Background()); err != nil {
			return err
		}
		fmt.Fprintln(a.out, "Đã kết thúc phiên làm việc; grant cấp trong phiên bị xóa, grant đã duyệt riêng (kg grants) vẫn giữ.")
		return nil
	}
	if err := a.client().SessionStart(context.Background()); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Phiên làm việc đã mở: grant user-presence/device tự cấp (kể cả PROD có grant đúng tên), không tự khóa. Kết thúc: kg session end.")
	return nil
}

func (a *app) cmdHash(args []string) error {
	if len(args) != 1 {
		return errors.New("dùng: kg hash <file>")
	}
	h, err := allowlist.FileHash(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, h)
	return nil
}

func (a *app) cmdSame(args []string) error {
	fs := newFS("same", a.errw)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 2 {
		return errors.New("dùng: kg same <a> <b> [<c> ...] (so mọi tên với tên đầu)")
	}
	r, err := a.client().Same(context.Background(), pos)
	if err != nil {
		return err
	}
	for _, it := range r.Items {
		fmt.Fprintf(a.out, "%-5s %s vs %s\n", it.Status, pos[0], it.Name)
	}
	return nil
}

func (a *app) cmdCp(args []string) error {
	fs := newFS("cp", a.errw)
	envName := fs.String("env-name", "", "đặt env_name cho mọi đích")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 2 || len(pos)%2 != 0 {
		return errors.New("dùng: kg cp <nguồn> <đích> [<nguồn2> <đích2> ...] [--env-name X]")
	}
	ca := wire.CopyArgs{EnvName: *envName}
	for i := 0; i < len(pos); i += 2 {
		ca.Pairs = append(ca.Pairs, wire.CopyPair{Src: pos[i], Dst: pos[i+1]})
	}
	r, err := a.client().Copy(context.Background(), ca)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Đã tạo %d secret: %s\n", len(r.Names), strings.Join(r.Names, ", "))
	return nil
}
