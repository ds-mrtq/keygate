package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"keygate/internal/approve"
)

// bprompt is the broker's own terminal in tests: queued hidden answers, captured output.
type bprompt struct {
	mu      sync.Mutex
	secrets []string
	out     bytes.Buffer
}

func (p *bprompt) ReadLine(ctx context.Context, _ string) (string, error) { return "", nil }
func (p *bprompt) ReadSecret(ctx context.Context, _ string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.secrets) == 0 {
		return "", io.EOF
	}
	v := p.secrets[0]
	p.secrets = p.secrets[1:]
	return v, nil
}
func (p *bprompt) ShowSecret(ctx context.Context, name, value string) error { return nil }
func (p *bprompt) Review(ctx context.Context, title, text string) error     { return nil }
func (p *bprompt) Out() io.Writer                                           { return io.Discard }

type testApp struct {
	*app
	bp        *bprompt
	out, errb *bytes.Buffer
	secrets   []string
	lines     []string
	approvals int
	mu        sync.Mutex
}

func newTestApp(t *testing.T, home string) *testApp {
	t.Helper()
	ta := &testApp{out: &bytes.Buffer{}, errb: &bytes.Buffer{}, bp: &bprompt{}}
	ta.app = &app{home: home, stdin: strings.NewReader(""), out: ta.out, errw: ta.errb, getenv: func(string) string { return "" }}
	ta.brokerPrompt = ta.bp
	ta.screenLocked = func() bool { return false } // tests must not depend on the real Win+L state
	ta.readSecret = func(prompt string, pipe bool) (string, error) {
		ta.mu.Lock()
		defer ta.mu.Unlock()
		if len(ta.secrets) == 0 {
			t.Fatalf("unexpected secret prompt %q", prompt)
		}
		v := ta.secrets[0]
		ta.secrets = ta.secrets[1:]
		return v, nil
	}
	ta.readLine = func(prompt string) (string, error) {
		ta.mu.Lock()
		defer ta.mu.Unlock()
		if len(ta.lines) == 0 {
			t.Fatalf("unexpected line prompt %q", prompt)
		}
		v := ta.lines[0]
		ta.lines = ta.lines[1:]
		return v, nil
	}
	ta.approver = approve.Func(func(ctx context.Context, prompt string) error {
		ta.mu.Lock()
		ta.approvals++
		ta.mu.Unlock()
		return nil
	})
	return ta
}

func (ta *testApp) do(t *testing.T, args ...string) string {
	t.Helper()
	ta.out.Reset()
	ta.errb.Reset()
	if code := ta.run(args); code != 0 {
		t.Fatalf("kg %v => exit %d\nstdout: %s\nstderr: %s", args, code, ta.out.String(), ta.errb.String())
	}
	return ta.out.String()
}

func (ta *testApp) startBroker(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	ta.brokerCtx = ctx
	ta.ready = func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- ta.cmdBroker(nil) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("broker exited: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("broker did not start")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
}

func TestEndToEnd(t *testing.T) {
	t.Setenv("KG_DEVKEY_BACKEND", "plain")
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	h1, h2 := filepath.Join(root, "h1"), filepath.Join(root, "h2")
	const master = "correct horse battery staple"
	const value = "s3cr3t-Value-ABC123xyz"

	// Device 1: init with a shared dir channel.
	d1 := newTestApp(t, h1)
	d1.secrets = []string{master, master}
	out := d1.do(t, "init", "--label", "laptop", "--dir", shared)
	m := regexp.MustCompile(`(?m)^\s+([A-Z2-7]{4}(?:-[A-Z2-7]{4})+)\s*$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("paper key not printed:\n%s", out)
	}
	paper := m[1]

	d1.startBroker(t)
	if err := os.WriteFile(filepath.Join(h1, "policy.yaml"), []byte(`grants:
  test/secret:
    kind: env
    allow_commands: ["go run ./testdata/printenv"]
    approval: user-presence
    ttl: 10m
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Policy not pinned yet: grants must be refused.
	d1.bp.secrets = []string{value} // typed on the BROKER terminal; the CLI never sees it
	d1.do(t, "set", "test/secret", "--kind", "env", "--env-name", "MY_TOKEN", "--env", "test")
	if strings.Contains(d1.out.String()+d1.errb.String(), value) {
		t.Fatal("kg set must not echo the value")
	}
	if code := d1.run([]string{"run", "--secret", "test/secret", "--", "go", "run", "./testdata/printenv", "MY_TOKEN"}); code == 0 {
		t.Fatal("run must fail before policy apply (pin missing)")
	}
	d1.do(t, "policy", "apply")

	out = d1.do(t, "run", "--secret", "test/secret", "--", "go", "run", "./testdata/printenv", "MY_TOKEN")
	if !strings.Contains(out, "plain=[kg:test/secret]") || !strings.Contains(out, "b64=[kg:test/secret]") {
		t.Fatalf("redaction missing:\n%s", out)
	}
	all := out + d1.errb.String()
	if strings.Contains(all, value) || strings.Contains(all, base64.StdEncoding.EncodeToString([]byte(value))) {
		t.Fatalf("secret leaked:\n%s", all)
	}
	if !strings.Contains(out, "err=[kg:test/secret]") { // stderr is merged into the one redaction stream
		t.Fatalf("stderr not redacted: %q", out)
	}
	// An absolute or relative path for the program is refused (C1).
	if code := d1.run([]string{"run", "--secret", "test/secret", "--", "./go", "run", "./testdata/printenv", "MY_TOKEN"}); code == 0 {
		t.Fatal("path-qualified program must be refused")
	}
	// A shell must stay blocked even if someone asks nicely.
	if code := d1.run([]string{"run", "--secret", "test/secret", "--", "sh", "-c", "echo $MY_TOKEN"}); code == 0 {
		t.Fatal("shell must be blocked")
	}
	if !strings.Contains(d1.do(t, "list"), "test/secret") {
		t.Fatal("list missing secret")
	}
	if !strings.Contains(d1.do(t, "audit", "verify"), "hợp lệ") {
		t.Fatal("audit verify")
	}
	if s := d1.do(t, "audit", "show", "--since", "1d"); strings.Contains(s, value) || !strings.Contains(s, "run") {
		t.Fatalf("audit show:\n%s", s)
	}

	// Device 2: request, owner adds, join via sync.
	d2 := newTestApp(t, h2)
	out = d2.do(t, "device", "request", "--label", "mac")
	code := regexp.MustCompile(`(?m)^([A-Z2-7]{40,})$`).FindStringSubmatch(out)
	if code == nil {
		t.Fatalf("no request code:\n%s", out)
	}
	d1.secrets = []string{master, paper}
	d1.lines = []string{"yes"}
	out = d1.do(t, "device", "add", code[1])
	pm := regexp.MustCompile(`--vault (vlt_[a-z2-7]+) --pin ([A-Z2-7-]+)`).FindStringSubmatch(out)
	if pm == nil {
		t.Fatalf("genesis pin not printed:\n%s", out)
	}
	// Joining without the pin, or with a wrong one, must fail.
	if c := d2.run([]string{"sync", "--via", "dir", "--dir", shared}); c == 0 {
		t.Fatal("join without pin must fail")
	}
	if c := d2.run([]string{"sync", "--via", "dir", "--dir", shared, "--vault", pm[1], "--pin", "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"}); c == 0 {
		t.Fatal("join with wrong pin must fail")
	}
	d2.do(t, "sync", "--via", "dir", "--dir", shared, "--vault", pm[1], "--pin", pm[2])

	d2.startBroker(t)
	if out := d2.do(t, "list"); !strings.Contains(out, "test/secret") {
		t.Fatalf("device 2 list lacks the secret:\n%s", out)
	}
	d1.do(t, "lock") // releases KG_HOME/lock
	if d1.do(t, "fingerprint") == "" {
		t.Fatal("fingerprint")
	}
}
