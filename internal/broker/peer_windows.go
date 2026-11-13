//go:build windows

package broker

import (
	"fmt"
	"net"
	"strings"
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
	return fmt.Sprintf("pid=%d exe=%s", pid, procImage(pid)) + parentChain(pid)
}

func procImage(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "?"
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return "?"
	}
	return windows.UTF16ToString(buf[:n])
}

func procStart(pid uint32) (windows.Filetime, bool) {
	var c, e, k, u windows.Filetime
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return c, false
	}
	defer windows.CloseHandle(h)
	return c, windows.GetProcessTimes(h, &c, &e, &k, &u) == nil
}

// parentChain names up to 3 ancestors of pid (" cha=bash.exe(12)<omp.exe(8)") so the approver sees
// which program ran kg. Informational only: a parent that started after its child is a reused pid
// and ends the chain.
func parentChain(pid uint32) string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snap)
	type proc struct {
		ppid uint32
		name string
	}
	procs := map[uint32]proc{}
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		procs[pe.ProcessID] = proc{pe.ParentProcessID, windows.UTF16ToString(pe.ExeFile[:])}
	}
	var parts []string
	cur := pid
	for len(parts) < 3 {
		p, ok := procs[cur]
		if !ok || p.ppid == 0 || p.ppid == cur {
			break
		}
		par, ok := procs[p.ppid]
		if !ok {
			break
		}
		cs, ok1 := procStart(cur)
		ps, ok2 := procStart(p.ppid)
		if !ok1 || !ok2 || ps.Nanoseconds() > cs.Nanoseconds() {
			break
		}
		parts = append(parts, fmt.Sprintf("%s(%d)", par.name, p.ppid))
		cur = p.ppid
	}
	if len(parts) == 0 {
		return ""
	}
	return " cha=" + strings.Join(parts, "<")
}
