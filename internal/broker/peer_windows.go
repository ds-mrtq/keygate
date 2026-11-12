//go:build windows

package broker

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID (Windows 10 1803+ AF_UNIX sockets).
const sioAFUnixGetPeerPID = 0x58000100

// peerInfo describes the process on the other end of conn ("pid=N exe=PATH").
func peerInfo(conn net.Conn) string {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return "pid=unavailable"
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return "pid=unavailable"
	}
	var pid uint32
	var ioErr error
	rc.Control(func(fd uintptr) {
		var ret uint32
		ioErr = windows.WSAIoctl(windows.Handle(fd), sioAFUnixGetPeerPID, nil, 0,
			(*byte)(unsafe.Pointer(&pid)), uint32(unsafe.Sizeof(pid)), &ret, nil, 0)
	})
	if ioErr != nil || pid == 0 {
		return "pid=unavailable"
	}
	exe := "?"
	if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); err == nil {
		defer windows.CloseHandle(h)
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
			exe = windows.UTF16ToString(buf[:n])
		}
	}
	return fmt.Sprintf("pid=%d exe=%s", pid, exe)
}
