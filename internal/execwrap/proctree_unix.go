//go:build !windows

package execwrap

import (
	"os/exec"
	"syscall"
)

// tree kills a whole process group.
type tree struct{ pgid int }

func newTree() *tree { return &tree{} }

func (t *tree) configure(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	setPdeathsig(cmd.SysProcAttr)
}

func (t *tree) attach(cmd *exec.Cmd) error {
	t.pgid = cmd.Process.Pid
	return nil
}

func (t *tree) kill() {
	if t.pgid > 0 {
		syscall.Kill(-t.pgid, syscall.SIGKILL)
	}
}

func (t *tree) close() {}
