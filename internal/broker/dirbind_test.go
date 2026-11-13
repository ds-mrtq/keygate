package broker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"keygate/internal/allowlist"
	"keygate/internal/api"
	"keygate/internal/approve"
	"keygate/internal/audit"
	"keygate/internal/broker/wire"
)

type promptLog struct {
	mu sync.Mutex
	l  []string
}

func (p *promptLog) add(s string) {
	p.mu.Lock()
	p.l = append(p.l, s)
	p.mu.Unlock()
}

func (p *promptLog) all() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.l, "\n")
}

func TestGrantBoundToRunDir(t *testing.T) {
	log := &promptLog{}
	f := newFixtureWith(t, 0, time.Hour, func(c *Config) {
		inner := c.Approver
		c.Approver = approve.Func(func(ctx context.Context, prompt string) error {
			log.add(prompt)
			return inner.Approve(ctx, prompt)
		})
	})
	req := helperRun(t, f, "")
	d1, d2 := t.TempDir(), t.TempDir()

	req.Dir = d1
	n := f.approvals.Load()
	f.mustRun(req)
	if f.approvals.Load() != n+1 {
		t.Fatalf("first run must ask once, asked %d", f.approvals.Load()-n)
	}
	// same directory: no new approval
	f.mustRun(req)
	if f.approvals.Load() != n+1 {
		t.Fatalf("same dir must reuse the grant, asked %d", f.approvals.Load()-n-1)
	}
	// a different directory is a different grant: a new approval is needed
	req.Dir = d2
	f.mustRun(req)
	if f.approvals.Load() != n+2 {
		t.Fatalf("other dir must ask again, asked %d", f.approvals.Load()-n)
	}
	// a symlinked path to d1 is the same canonical directory
	link := filepath.Join(t.TempDir(), "lnk")
	if os.Symlink(d1, link) == nil {
		req.Dir = link
		f.mustRun(req)
		if f.approvals.Load() != n+2 {
			t.Fatalf("symlink to a granted dir must reuse the grant")
		}
	}
	// the approval text shows the canonical directory, and so do grants and the audit log
	for _, d := range []string{d1, d2} {
		if !strings.Contains(log.all(), "(thư mục: "+allowlist.CanonDir(d)+")") {
			t.Errorf("approval prompt lacks the directory %q:\n%s", d, log.all())
		}
	}
	gv, err := f.cli.Grants(context.Background())
	if err != nil || len(gv) != 2 {
		t.Fatalf("grants: %+v %v", gv, err)
	}
	got := map[string]bool{gv[0].Dir: true, gv[1].Dir: true}
	if !got[allowlist.CanonDir(d1)] || !got[allowlist.CanonDir(d2)] {
		t.Fatalf("grant dirs: %+v", gv)
	}
	data, _ := os.ReadFile(filepath.Join(f.home, "audit", "ledger.jsonl"))
	if !strings.Contains(string(data), `"dir":`) {
		t.Fatal("audit entries must carry the run directory")
	}
	// durable grants keep the directory across a restart; one without dir would not load
	f.restart()
	n = f.approvals.Load()
	req.Dir = d1
	f.mustRun(req)
	if f.approvals.Load() != n {
		t.Fatalf("after restart: no prompt expected for the granted dir, got %d", f.approvals.Load()-n)
	}
}

func TestApprovalCommandKeepsDir(t *testing.T) {
	long := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		long = append(long, "argument-number-"+strings.Repeat("x", 20))
	}
	got := approvalCommand(long, `C:\work\repo`)
	if !strings.HasSuffix(got, `(thư mục: C:\work\repo)`) || len([]rune(got)) > approve.MaxPrompt {
		t.Fatalf("%d runes: %q", len([]rune(got)), got)
	}
	if approve.Sanitize(got, approve.MaxPrompt) != got {
		t.Fatal("prompt must survive the later Sanitize unchanged")
	}
}

func TestPinChangedBeforeExecRefusesRun(t *testing.T) {
	log := &promptLog{}
	script := filepath.Join(t.TempDir(), "job.txt")
	if err := os.WriteFile(script, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newFixtureWith(t, 0, time.Hour, func(c *Config) {
		inner := c.Approver
		c.Approver = approve.Func(func(ctx context.Context, prompt string) error {
			log.add(prompt)
			if strings.Contains(prompt, "TestBrokerHelper") {
				// the human takes a while to approve: the pinned file changes after Check
				if err := os.WriteFile(script, []byte("two"), 0o644); err != nil {
					return err
				}
			}
			return inner.Approve(ctx, prompt)
		})
	})
	base := helperRun(t, f, "")
	exe := base.Argv[0]
	exeHash, _ := allowlist.FileHash(exe)
	sh, _ := allowlist.FileHash(script)
	f.policy(`grants:
  ebs/test/tok:
    allow_commands: ["\"`+filepath.ToSlash(exe)+`\" `+exeHash+` -test.run=TestBrokerHelper path:`+filepath.ToSlash(script)+` `+sh+`"]
    approval: user-presence
`, true)
	req := api.RunRequest{Secrets: base.Secrets, Argv: []string{exe, "-test.run=TestBrokerHelper", script}, Agent: "t"}
	var out strings.Builder
	rc, err := f.cli.Run(context.Background(), req, &out, &out)
	if err == nil || code(err) != wire.CodeBlocked {
		t.Fatalf("a pinned file changed after approval must refuse the run: code=%d err=%v out=%q", rc, err, out.String())
	}
	if strings.Contains(out.String(), "s3cr3t") {
		t.Fatal("the child must not have run")
	}
	evs := auditEvents(t, f)
	if len(evs) == 0 || evs[len(evs)-1] != audit.EvDeny {
		t.Fatalf("the refusal must be audited as a deny: %v", evs)
	}
}
