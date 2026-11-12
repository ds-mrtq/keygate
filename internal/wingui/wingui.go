// Package wingui is the Windows front end of the broker: dialogs, tray icon and the broker.Prompter
// built on them. Secret values only ever pass through Win32 dialogs owned by this process, never
// through PowerShell (a GPO transcript could record its output) and never through the socket.
package wingui

import (
	"context"
	"errors"
	"io"
	"strings"
)

// ErrCanceled is returned when the user closes a dialog with Cancel.
var ErrCanceled = errors.New("người dùng hủy")

// errLocked is returned by the interactive Prompter methods while the screen is locked.
var errLocked = errors.New("màn hình đang khóa: thao tác này cần làm tại máy, hoặc nhập từ web app trên điện thoại")

// Prompter implements broker.Prompter with dialogs. Log receives the broker's log lines.
type Prompter struct {
	Log    io.Writer
	Locked func() bool // true = nobody can see a dialog: interactive methods fail at once
}

func (p *Prompter) check() error {
	if p.Locked != nil && p.Locked() {
		return errLocked
	}
	return nil
}

// ReadSecret shows the hidden-input dialog.
func (p *Prompter) ReadSecret(ctx context.Context, prompt string) (string, error) {
	if err := p.check(); err != nil {
		return "", err
	}
	return Secret(ctx, cleanPrompt(prompt))
}

// ReadLine shows a visible one-line input dialog.
func (p *Prompter) ReadLine(ctx context.Context, prompt string) (string, error) {
	if err := p.check(); err != nil {
		return "", err
	}
	return Line(ctx, prompt)
}

// Review shows a read-only text box the user must dismiss with Continue before approving.
func (p *Prompter) Review(ctx context.Context, title, text string) error {
	if err := p.check(); err != nil {
		return err
	}
	return Review(ctx, title, text)
}

// ShowSecret shows a revealed value in a dialog that closes itself after 60 seconds.
func (p *Prompter) ShowSecret(ctx context.Context, name, value string) error {
	if err := p.check(); err != nil {
		return err
	}
	return ShowSecret(ctx, name, value)
}

// Out is the broker log.
func (p *Prompter) Out() io.Writer {
	if p.Log == nil {
		return io.Discard
	}
	return p.Log
}

// cleanPrompt turns the console wording of the broker's value prompt into dialog wording:
// `[broker] Nhập giá trị cho "x" (ẩn; yêu cầu từ y): ` -> "Nhập giá trị cho "x"\nyêu cầu từ y".
func cleanPrompt(s string) string {
	s = strings.TrimPrefix(s, "[broker] ")
	s = strings.TrimRight(s, " :")
	if i := strings.Index(s, " (ẩn; yêu cầu từ "); i >= 0 {
		s = s[:i] + "\nyêu cầu từ " + strings.TrimSuffix(s[i+len(" (ẩn; yêu cầu từ "):], ")")
	}
	return s
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
