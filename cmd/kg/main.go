// Command kg is the KeyGate CLI: a thin client of the broker plus the owner/device commands.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"keygate/internal/approve"
	"keygate/internal/broker"
	"keygate/internal/broker/wire"
	"keygate/internal/brokerclient"
	"keygate/internal/devkey"
	"keygate/internal/fsx"
	"keygate/internal/store"
	"keygate/internal/tty"
)

// app carries everything a command needs, so tests can run commands in-process.
type app struct {
	home   string
	stdin  io.Reader
	out    io.Writer
	errw   io.Writer
	getenv func(string) string

	// readSecret reads hidden input (value, passwords). pipe=true allows non-terminal stdin.
	readSecret func(prompt string, pipe bool) (string, error)
	// readLine reads a visible answer.
	readLine func(prompt string) (string, error)
	// approver gates the broker's unlock/grants and `kg approve`; nil = approve.Platform().
	approver approve.Approver
	// brokerPrompt is the broker's own terminal (value entry, device approvals); nil = process stdin.
	brokerPrompt broker.Prompter
	// screenLocked overrides the broker's workstation-lock probe (tests); nil = broker.ScreenLocked.
	screenLocked func() bool
	// brokerCtx, when set, replaces the signal context of `kg broker` (tests).
	brokerCtx context.Context
	// ready is closed by `kg broker` once the socket is listening (tests); may be nil.
	ready func()
	// defaultCmd names the command run without arguments ("" = print usage); nil = usage.
	defaultCmd func() string
}

func newApp() (*app, error) {
	home, err := store.DefaultHome()
	if err != nil {
		return nil, err
	}
	return &app{home: home, stdin: os.Stdin, out: os.Stdout, errw: os.Stderr, getenv: os.Getenv,
		readSecret: tty.ReadSecret, readLine: tty.ReadLine, defaultCmd: defaultCommand}, nil
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		// Needs no KG_HOME, so it works before a home directory exists.
		os.Exit((&app{out: os.Stdout, errw: os.Stderr}).run(os.Args[1:]))
	}
	a, err := newApp()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kg:", err)
		os.Exit(1)
	}
	os.Exit(a.run(os.Args[1:]))
}

const usage = `kg: KeyGate, kho khóa cho AI agent

Dùng: kg <lệnh> [tham số]
  init | set | import | delete | list | session start|end | hash | same | cp | run | resolve | grant | reveal
  conflicts | resolve-conflict | sync | fingerprint
  device request|add|revoke | channel add | recover | approve
  broker | grants [revoke] | tray (Windows: khay hệ thống, dùng kgw.exe) | policy apply|pin | audit verify|show | hook check | mcp | lock | status | version

Xem docs/CLI.md để biết chi tiết.
`

func (a *app) run(args []string) int {
	if len(args) == 0 && a.defaultCmd != nil {
		if c := a.defaultCmd(); c != "" {
			args = []string{c}
		}
	}
	if len(args) == 0 {
		fmt.Fprint(a.errw, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "init":
		err = a.cmdInit(rest)
	case "set":
		err = a.cmdSet(rest)
	case "import":
		err = a.cmdImport(rest)
	case "list":
		err = a.cmdList(rest)
	case "run":
		err = a.cmdRun(rest, false)
	case "resolve":
		err = a.cmdRun(rest, true)
	case "grant":
		err = a.cmdGrant(rest)
	case "reveal":
		err = a.cmdReveal(rest)
	case "conflicts":
		err = a.cmdConflicts(rest)
	case "resolve-conflict":
		err = a.cmdResolveConflict(rest)
	case "sync":
		err = a.cmdSync(rest)
	case "session":
		err = a.cmdSession(rest)
	case "hash":
		err = a.cmdHash(rest)
	case "same":
		err = a.cmdSame(rest)
	case "cp":
		err = a.cmdCp(rest)
	case "delete":
		err = a.cmdDelete(rest)
	case "fingerprint":
		err = a.cmdFingerprint(rest)
	case "device":
		err = a.cmdDevice(rest)
	case "recover":
		err = a.cmdRecover(rest)
	case "approve":
		err = a.cmdApprove(rest)
	case "broker":
		err = a.cmdBroker(rest)
	case "grants":
		err = a.cmdGrants(rest)
	case "tray":
		err = a.cmdTray(rest)
	case "policy":
		err = a.cmdPolicy(rest)
	case "audit":
		err = a.cmdAudit(rest)
	case "hook":
		return a.cmdHook(rest)
	case "channel":
		err = a.cmdChannel(rest)
	case "mcp":
		err = a.cmdMCP(rest)
	case "lock":
		err = a.cmdLock(rest)
	case "status":
		err = a.cmdStatus(rest)
	case "help", "-h", "--help":
		fmt.Fprint(a.out, usage)
		return 0
	case "version", "--version":
		if len(rest) > 0 {
			fmt.Fprintln(a.errw, "kg: dùng: kg version")
			return 2
		}
		fmt.Fprintln(a.out, versionLine())
		return 0
	default:
		fmt.Fprintf(a.errw, "kg: lệnh lạ %q\n\n%s", cmd, usage)
		return 2
	}
	if err == nil {
		return 0
	}
	var ec exitCodeErr
	if errors.As(err, &ec) {
		if ec.err != nil {
			fmt.Fprintln(a.errw, "kg:", ec.err)
		}
		return ec.code
	}
	fmt.Fprintln(a.errw, "kg:", err)
	var be *brokerclient.Error
	if errors.As(err, &be) && be.Code == wire.CodePending {
		return exitPending // waiting for the phone: approve there, then run the command again
	}
	return 1
}

// exitPending is EX_TEMPFAIL: the request is open on the phone, retry after approving.
const exitPending = 75

// exitCodeErr carries a specific process exit code (child exit codes).
type exitCodeErr struct {
	code int
	err  error
}

func (e exitCodeErr) Error() string { return fmt.Sprint(e.err) }

// ---- flag helpers ----

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func newFS(name string, errw io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("kg "+name, flag.ContinueOnError)
	fs.SetOutput(errw)
	return fs
}

// parseArgs allows flags before, between and after positional arguments.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// splitDash splits args at the first "--".
func splitDash(args []string) (before, after []string, found bool) {
	for i, s := range args {
		if s == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

// ---- shared plumbing ----

func (a *app) client() *brokerclient.Client {
	c := brokerclient.New(broker.SockPath(a.home))
	c.Note = func(msg string) { fmt.Fprintln(a.errw, "kg:", msg) }
	return c
}

func (a *app) devPassword(confirm bool) (string, error) {
	p, err := a.readSecret("Mật khẩu mở khóa thiết bị: ", true)
	if err != nil {
		return "", err
	}
	if confirm {
		p2, err := a.readSecret("Nhập lại: ", true)
		if err != nil {
			return "", err
		}
		if p != p2 {
			return "", errors.New("hai lần nhập không khớp")
		}
	}
	return p, nil
}

func (a *app) openKeys() (devkey.Store, error) {
	return devkey.Open(a.home, devkey.Options{Password: a.devPassword})
}

// openStore opens KG_HOME in-process (commands that do not need the broker).
func (a *app) openStore() (*store.Store, error) {
	ks, err := a.openKeys()
	if err != nil {
		return nil, err
	}
	id, err := store.LoadIdentity(a.home, ks)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(a.home, id)
	if err != nil {
		return nil, lockedHint(err)
	}
	return st, nil
}

// lockedHint explains ErrLocked: the broker (or another kg) holds KG_HOME/lock.
func lockedHint(err error) error {
	if errors.Is(err, fsx.ErrLocked) {
		return errors.New("KG_HOME đang bị khóa: chạy kg lock (hoặc Khóa ở khay hệ thống) rồi chạy lại")
	}
	return err
}

func (a *app) agent(def string) string {
	if v := a.getenv("KG_AGENT"); v != "" {
		return v
	}
	return def
}

func sigCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

func readAllLimited(r io.Reader, n int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if err == nil && int64(len(b)) > n {
		err = errors.New("đầu vào quá lớn")
	}
	return b, err
}
