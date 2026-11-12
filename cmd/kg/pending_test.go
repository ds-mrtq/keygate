package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keygate/internal/broker"
	"keygate/internal/broker/wire"
)

// A broker answer `pending` ends the command with exit code 75 and the note shows up on stderr.
func TestPendingExitCode75(t *testing.T) {
	home := t.TempDir()
	ln, err := net.Listen("unix", broker.SockPath(home))
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		bufio.NewReader(c).ReadString('\n')
		enc := json.NewEncoder(c)
		enc.Encode(wire.Frame{T: wire.FrameNote, Msg: "đang chờ duyệt trên điện thoại (KeyGate, yêu cầu abc123)"})
		enc.Encode(wire.Frame{T: wire.FrameErr, Code: wire.CodePending, Msg: "đang chờ duyệt trên điện thoại (yêu cầu abc123); duyệt xong chạy lại lệnh"})
	}()
	var out, errb bytes.Buffer
	a := &app{home: home, out: &out, errw: &errb, getenv: func(string) string { return "" }}
	if code := a.run([]string{"status"}); code != 75 {
		t.Fatalf("exit %d, want 75\nstderr: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "kg: đang chờ duyệt trên điện thoại (KeyGate, yêu cầu abc123)") {
		t.Fatalf("stderr lacks the note: %q", errb.String())
	}
	_ = os.Remove(filepath.Join(home, broker.SockName))
}
