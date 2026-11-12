//go:build linux

package broker

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// peerInfo describes the process on the other end of conn ("pid=N exe=PATH") via SO_PEERCRED.
func peerInfo(conn net.Conn) string {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return "pid=unavailable"
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return "pid=unavailable"
	}
	var cred *unix.Ucred
	var ioErr error
	rc.Control(func(fd uintptr) { cred, ioErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if ioErr != nil || cred == nil {
		return "pid=unavailable"
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", cred.Pid))
	if err != nil {
		exe = "?"
	}
	return fmt.Sprintf("pid=%d uid=%d exe=%s", cred.Pid, cred.Uid, exe)
}
