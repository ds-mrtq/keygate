//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"keygate/internal/tty"
)

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

// operator is the person at the broker's terminal: it answers prompts it sees on the PTY.
type operator struct {
	mu      sync.Mutex
	screen  bytes.Buffer // everything the broker printed on its terminal
	pending int          // screen offset not yet scanned for prompts
	answers map[string]string
}

func (o *operator) watch(master *os.File) {
	buf := make([]byte, 4096)
	for {
		n, err := master.Read(buf)
		if n > 0 {
			o.mu.Lock()
			o.screen.Write(buf[:n])
			for {
				rest := o.screen.String()[o.pending:]
				at, ans := -1, ""
				for p, a := range o.answers {
					if i := strings.Index(rest, p); i >= 0 && (at < 0 || i < at) {
						at, ans = i+len(p), a
					}
				}
				if at < 0 {
					break
				}
				o.pending += at
				master.WriteString(ans + "\n")
			}
			o.mu.Unlock()
		}
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

// TestSingleMachineLinux: one Linux device with the production approver (no user-presence on
// Linux) applies a policy and runs a granted command with input typed only at the broker's own
// terminal (the device unlock password), without a second device.
func TestSingleMachineLinux(t *testing.T) {
	t.Setenv("KG_DEVKEY_BACKEND", "")
	t.Setenv("KG_TEST_APPROVE", "")
	const master = "correct horse battery staple"
	const devPw = "fake-device-pw-1"
	const value = "s3cr3t-Value-ABC123xyz"
	home := filepath.Join(t.TempDir(), "h")

	d := newTestApp(t, home)
	d.approver = nil // broker default: approve.Platform()
	d.readSecret = func(prompt string, _ bool) (string, error) {
		if strings.Contains(prompt, "chủ") {
			return master, nil
		}
		return devPw, nil
	}
	d.do(t, "init", "--label", "laptop")
	if _, err := os.Stat(filepath.Join(home, "device.key.enc")); err != nil {
		t.Fatalf("device key must use the password-protected file backend: %v", err)
	}

	pm, ps := openPTY(t)
	op := &operator{answers: map[string]string{
		"Mật khẩu mở khóa thiết bị": devPw,
		"[broker] Nhập giá trị":     value,
	}}
	go op.watch(pm)
	d.brokerPrompt = tty.NewConsole(ps, ps, ps)

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	d.brokerCtx, d.ready = ctx, func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- d.cmdBroker([]string{"--approval-wait", "10s"}) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("broker exited: %v", err)
	case <-time.After(60 * time.Second):
		t.Fatal("broker did not start")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})

	if err := os.WriteFile(filepath.Join(home, "policy.yaml"), []byte(`grants:
  test/secret:
    kind: env
    allow_commands: ["go run ./testdata/printenv"]
    approval: user-presence
    ttl: 10m
`), 0o600); err != nil {
		t.Fatal(err)
	}
	d.do(t, "set", "test/secret", "--kind", "env", "--env-name", "MY_TOKEN", "--env", "test")
	d.do(t, "policy", "apply")
	d.do(t, "session", "end") // the grant itself must be approved, not ride on the start-up session
	out := d.do(t, "run", "--secret", "test/secret", "--", "go", "run", "./testdata/printenv", "MY_TOKEN")
	if !strings.Contains(out, "plain=[kg:test/secret]") || strings.Contains(out+d.errb.String(), value) {
		t.Fatalf("run output not masked:\n%s", out)
	}
	screen := op.text()
	if strings.Contains(screen, value) || strings.Contains(screen, devPw) {
		t.Fatalf("a hidden answer was echoed on the broker terminal:\n%s", screen)
	}
	if !strings.Contains(screen, "áp dụng policy.yaml") || !strings.Contains(screen, "cho phép dùng secret test/secret") {
		t.Fatalf("broker terminal lacks the review text:\n%s", screen)
	}
	audit := d.do(t, "audit", "show", "--since", "1d")
	if !strings.Contains(audit, "approval=tty-password") {
		t.Fatalf("audit must record the terminal-password approval:\n%s", audit)
	}
}
