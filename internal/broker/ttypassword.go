package broker

import (
	"context"
	"errors"
	"fmt"

	"keygate/internal/devkey"
	"keygate/internal/tty"
)

// TerminalPrompter is a Prompter that can read hidden input from an interactive terminal attached
// to the broker process (stdin when it is a terminal, else the controlling terminal), never from a
// pipe or file. It returns tty.ErrNoTerminal when there is no such terminal.
type TerminalPrompter interface {
	ReadTerminalSecret(ctx context.Context, prompt string) (string, error)
}

// byTTYPassword is the approvalRes.by (and audit approval) of a device password typed at the
// broker's terminal.
const byTTYPassword = "tty-password"

const maxPasswordTries = 3

var errWrongPassword = errors.New("sai mật khẩu thiết bị")

func filePasswordCheck(home, dev string) func(string) error {
	return func(pw string) error {
		_, err := devkey.NewFile(home, devkey.Options{Password: func(bool) (string, error) { return pw, nil }}).Load(dev)
		return err
	}
}

// approveByTTYPassword is user presence where the OS has none (Linux): the device unlock password,
// read only from an interactive terminal attached to the broker process. ok=false when that is not
// possible (no terminal: stdin a pipe or file; no password-protected device key); the caller then
// asks for approval from another device. Nothing a client sends can answer this prompt.
func (b *Broker) approveByTTYPassword(ctx context.Context, prompt string) (res approvalRes, ok bool, err error) {
	tp, isTP := b.cfg.Prompt.(TerminalPrompter)
	if !isTP || b.cfg.CheckPassword == nil {
		return approvalRes{}, false, nil
	}
	fmt.Fprintf(b.out(), "\n[%s]\n", prompt)
	for i := 1; i <= maxPasswordTries; i++ {
		pw, err := tp.ReadTerminalSecret(ctx, "Mật khẩu mở khóa thiết bị để duyệt: ")
		if errors.Is(err, tty.ErrNoTerminal) {
			b.logf("không có terminal tương tác gắn với broker: mật khẩu thiết bị không được dùng để duyệt, cần duyệt từ thiết bị khác")
			return approvalRes{}, false, nil
		}
		if err != nil {
			return approvalRes{}, true, err
		}
		if b.cfg.CheckPassword(pw) == nil {
			b.touch()
			return approvalRes{choice: "allow", by: byTTYPassword}, true, nil
		}
		n := b.pwFailures.Add(1)
		b.logf("mật khẩu thiết bị sai (lần %d/%d; %d lần sai từ khi broker chạy)", i, maxPasswordTries, n)
	}
	return approvalRes{}, true, fmt.Errorf("%w %d lần", errWrongPassword, maxPasswordTries)
}
