//go:build !windows

package execwrap

import (
	"os/exec"
	"sync"
	"syscall"
)

// tree kills a whole process group. kill may run on exec's context-watch goroutine while attach runs.
type tree struct {
	mu   sync.Mutex
	pgid int
}

func newTree() *tree { return &tree{} }

func (t *tree) configure(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	setPdeathsig(cmd.SysProcAttr)
}

func (t *tree) attach(cmd *exec.Cmd) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pgid = cmd.Process.Pid
	return nil
}

func (t *tree) kill() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pgid > 0 {
		syscall.Kill(-t.pgid, syscall.SIGKILL)
	}
}

func (t *tree) close() {}
