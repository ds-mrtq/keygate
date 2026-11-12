//go:build darwin

package broker

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerInfo reports the peer pid (LOCAL_PEERPID); macOS gives no cheap executable path here.
func peerInfo(conn net.Conn) string {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return "pid=unavailable"
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return "pid=unavailable"
	}
	var pid int
	var ioErr error
	rc.Control(func(fd uintptr) { pid, ioErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID) })
	if ioErr != nil || pid == 0 {
		return "pid=unavailable"
	}
	return fmt.Sprintf("pid=%d exe=unavailable", pid)
}
