//go:build linux

package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"keygate/internal/approve"
	"keygate/internal/broker/wire"
	"keygate/internal/devkey"
	"keygate/internal/store"
	"keygate/internal/tty"
)

const goodPw = "fake-device-pw-1"

func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

// operator is the person at the broker's terminal: each time a prompt appears it types the answer.
type operator struct {
	mu      sync.Mutex
	screen  bytes.Buffer
	scanned int
	answers map[string]func(screen string) string
}

func (o *operator) watch(master *os.File) {
	buf := make([]byte, 4096)
	for {
		n, err := master.Read(buf)
		o.mu.Lock()
		o.screen.Write(buf[:n])
		for {
			rest := o.screen.String()[o.scanned:]
			at, ans := -1, (func(string) string)(nil)
			for p, a := range o.answers {
				if i := strings.Index(rest, p); i >= 0 && (at < 0 || i < at) {
					at, ans = i+len(p), a
				}
			}
			if at < 0 {
				break
			}
			o.scanned += at
			master.WriteString(ans(o.screen.String()) + "\n")
		}
		o.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (o *operator) text() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.screen.String()
}

func say(s string) func(string) string { return func(string) string { return s } }

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// linuxFixture is a broker as on Linux: the production approver has no user-presence, and the
// device password is checked by check (which counts its calls).
func linuxFixture(t *testing.T, console *tty.Console, checks *atomic.Int64) *fixture {
	return newFixtureWith(t, 0, time.Hour, func(c *Config) {
		c.Approver = approve.Func(func(context.Context, string) error { return approve.ErrUnsupported })
		c.Prompt = console
		c.ApprovalWait = 10 * time.Second
		c.CheckPassword = func(pw string) error {
			checks.Add(1)
			if pw != goodPw {
				return errors.New("wrong device password")
			}
			return nil
		}
	})
}

func ttyConsole(t *testing.T, answers map[string]func(string) string) (*tty.Console, *operator) {
	master, slave := openPTY(t)
	op := &operator{answers: answers}
	go op.watch(master)
	c := tty.NewConsole(slave, slave, slave)
	c.SetControllingTerminal(func() (*os.File, error) { return nil, errors.New("none") })
	return c, op
}

func TestTTYPasswordApprovesGrant(t *testing.T) {
	var checks atomic.Int64
	c, op := ttyConsole(t, map[string]func(string) string{"Mật khẩu mở khóa thiết bị để duyệt: ": say(goodPw)})
	f := linuxFixture(t, c, &checks)
	f.put("", "ebs/test/a", "test")
	f.policy(basePolicy, true)
	g, err := f.cli.RequestGrant(context.Background(), "ebs/test/a", sqlArgv, "t")
	if err != nil || g.Approval != "user-presence" {
		t.Fatalf("grant with the device password typed at the broker TTY: %+v %v", g, err)
	}
	if checks.Load() != 1 {
		t.Fatalf("password checks = %d, want 1", checks.Load())
	}
	if s := op.text(); !strings.Contains(s, "[KeyGate: cho phép dùng secret ebs/test/a cho lệnh: ") || strings.Contains(s, goodPw) {
		t.Fatalf("broker terminal must show the approval text and never echo the password:\n%s", s)
	}
	f.b.mu.Lock()
	var by string
	for _, ge := range f.b.grants {
		by = ge.By
	}
	f.b.mu.Unlock()
	if by != byTTYPassword || apprName(by) != byTTYPassword {
		t.Fatalf("grant approved by %q, want %q", by, byTTYPassword)
	}
}

func TestTTYPasswordWrongIsRefusedAndCounted(t *testing.T) {
	var checks atomic.Int64
	c, op := ttyConsole(t, map[string]func(string) string{"Mật khẩu mở khóa thiết bị để duyệt: ": say("not-the-password")})
	f := linuxFixture(t, c, &checks)
	f.put("", "ebs/test/a", "test")
	f.policy(basePolicy, true)
	for round := 1; round <= 2; round++ {
		if _, err := f.cli.RequestGrant(context.Background(), "ebs/test/a", sqlArgv, "t"); code(err) != wire.CodeDenied {
			t.Fatalf("round %d: wrong password must be refused, got %v", round, err)
		}
		if n := f.b.pwFailures.Load(); n != int64(round*maxPasswordTries) {
			t.Fatalf("round %d: failures counted = %d", round, n)
		}
	}
	if s := op.text(); !strings.Contains(s, fmt.Sprintf("mật khẩu thiết bị sai (lần %d/%d; %d lần", maxPasswordTries, maxPasswordTries, 2*maxPasswordTries)) {
		t.Fatalf("broker terminal must report the wrong passwords:\n%s", s)
	}
	if st, _ := f.cli.Status(context.Background()); len(st.Grants) != 0 {
		t.Fatalf("no grant may exist: %+v", st.Grants)
	}
}

// The password reaching the broker through a pipe on its stdin (what a client, an agent or a
// script can arrange) is never a user-presence approval: the broker asks for another device.
func TestTTYPasswordRefusedFromPipe(t *testing.T) {
	var checks atomic.Int64
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	go func() {
		for i := 0; i < 20; i++ {
			if _, err := w.WriteString(goodPw + "\n"); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	out := &syncBuf{}
	c := tty.NewConsole(r, r, out)
	c.SetControllingTerminal(func() (*os.File, error) { return nil, errors.New("none") })
	f := linuxFixture(t, c, &checks)
	f.put("", "ebs/test/a", "test")
	f.policy(basePolicy, true)
	if _, err := f.cli.RequestGrant(context.Background(), "ebs/test/a", sqlArgv, "t"); err == nil {
		t.Fatal("a password piped into the broker must not approve")
	}
	if checks.Load() != 0 {
		t.Fatalf("password checks = %d, want 0: piped input is never a password", checks.Load())
	}
	if s := out.String(); !strings.Contains(s, "không có terminal tương tác") || !strings.Contains(s, "kg approve ") {
		t.Fatalf("broker must fall back to approval from another device:\n%s", s)
	}
}

// approval: device is untouched: no password prompt, and a signature from the broker's own
// device is still refused.
func TestDeviceApprovalIgnoresTTYPassword(t *testing.T) {
	var checks atomic.Int64
	var home string
	selfSign := func(screen string) string {
		m := regexp.MustCompile(`kg approve (\S+)`).FindAllStringSubmatch(screen, -1)
		if m == nil {
			return ""
		}
		ch, err := approve.DecodeChallenge(m[len(m)-1][1])
		if err != nil {
			return ""
		}
		id, err := store.LoadIdentity(home, devkey.NewPlain(home))
		if err != nil {
			return ""
		}
		return approve.Sign(ch, id.Dev, id.EdPriv)
	}
	c, op := ttyConsole(t, map[string]func(string) string{
		"Mật khẩu mở khóa thiết bị":  say(goodPw),
		"Dán chuỗi chữ ký vào đây: ": selfSign,
	})
	f := linuxFixture(t, c, &checks)
	home = f.home
	f.put("", "ebs/test/a", "test")
	f.policy(strings.Replace(basePolicy, "    approval: user-presence\n    ttl: 10m", "    approval: device\n    ttl: 10m", 1), true)
	if _, err := f.cli.RequestGrant(context.Background(), "ebs/test/a", sqlArgv, "t"); err == nil || !strings.Contains(err.Error(), "thiết bị khác máy chạy broker") {
		t.Fatalf("approval: device must refuse the broker's own device signature, got %v", err)
	}
	s := op.text()
	if checks.Load() != 0 || strings.Contains(s, "Mật khẩu mở khóa thiết bị") {
		t.Fatalf("approval: device must not ask for the device password (checks=%d):\n%s", checks.Load(), s)
	}
	if !strings.Contains(s, "kg approve ") {
		t.Fatalf("approval: device must show the challenge:\n%s", s)
	}
}
