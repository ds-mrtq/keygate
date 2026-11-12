//go:build windows

package execwrap

import (
	"os/exec"
	"unsafe"

	"keygate/internal/pshell"

	"golang.org/x/sys/windows"
)

// tree kills a whole process tree through a Job Object (KILL_ON_JOB_CLOSE).
type tree struct{ job windows.Handle }

func newTree() *tree { return &tree{} }

// configure: under `kgw tray` (no console of its own) every wrapped console program would get a new,
// visible console window; CREATE_NO_WINDOW gives it a hidden one that its own children inherit.
// Output still reaches the caller through the pipes. No effect when the broker runs in a terminal.
func (t *tree) configure(cmd *exec.Cmd) { pshell.Hide(cmd) }

func (t *tree) attach(cmd *exec.Cmd) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		windows.CloseHandle(job)
		return err
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		windows.CloseHandle(job)
		return err
	}
	t.job = job
	return nil
}

func (t *tree) kill() {
	if t.job != 0 {
		windows.TerminateJobObject(t.job, 1)
	}
}

func (t *tree) close() {
	if t.job != 0 {
		windows.CloseHandle(t.job) // KILL_ON_JOB_CLOSE reaps whatever is left
		t.job = 0
	}
}
