// Package tty reads hidden input (passwords, secret values) from the user's terminal.
package tty

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// ErrNoTerminal is returned when hidden input needs a terminal and stdin is a pipe or file.
var ErrNoTerminal = errors.New("cần terminal tương tác (stdin đang là pipe/file)")

// stdinReader is shared so that piped input is not lost between successive prompts.
var stdinReader = bufio.NewReader(os.Stdin)

// ReadSecret prints prompt to stderr and reads one line without echo from the terminal.
// When stdin is not a terminal it fails with ErrNoTerminal unless allowPipe is true, in which
// case the line is read as is (scripting and tests).
func ReadSecret(prompt string, allowPipe bool) (string, error) {
	if isTerminal(os.Stdin) {
		restore, err := disableEcho(os.Stdin)
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, prompt)
		defer fmt.Fprintln(os.Stderr)
		defer restore()
		return readLine(stdinReader)
	}
	if !allowPipe {
		return "", ErrNoTerminal
	}
	return readLine(stdinReader)
}

// ReadLine prints prompt to stderr and reads one visible line.
func ReadLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	return readLine(stdinReader)
}

// IsTerminal reports whether f is an interactive terminal.
func IsTerminal(f *os.File) bool { return isTerminal(f) }

func readLine(r *bufio.Reader) (string, error) {
	s, err := r.ReadString('\n')
	if err != nil && (err != io.EOF || s == "") {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

type lineResult struct {
	s   string
	err error
}

// Console serves prompts on the broker's own terminal through ONE reader goroutine, so a
// cancelled prompt never leaves a stray reader that swallows the next typed line.
type Console struct {
	in    *os.File // used only to switch echo; may be nil for pipes
	out   io.Writer
	lines chan lineResult
	mu    sync.Mutex // one prompt at a time
}

// NewConsole starts the reader goroutine on r. in (optional) is the terminal file for hidden input.
func NewConsole(r io.Reader, in *os.File, out io.Writer) *Console {
	c := &Console{in: in, out: out, lines: make(chan lineResult, 1)}
	br := bufio.NewReader(r)
	go func() {
		for {
			s, err := readLine(br)
			c.lines <- lineResult{s, err}
			if err != nil {
				close(c.lines)
				return
			}
		}
	}()
	return c
}

// Stdin returns a Console on the process stdin/stderr.
func Stdin() *Console { return NewConsole(os.Stdin, os.Stdin, os.Stderr) }

// Out returns the console output writer.
func (c *Console) Out() io.Writer { return c.out }

func (c *Console) read(ctx context.Context, prompt string, hidden bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select { // drop type-ahead typed while nobody asked
	case <-c.lines:
	default:
	}
	if hidden && c.in != nil && isTerminal(c.in) {
		restore, err := disableEcho(c.in)
		if err != nil {
			return "", err
		}
		defer restore()
	}
	fmt.Fprint(c.out, prompt)
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r, ok := <-c.lines:
		if !ok {
			return "", io.EOF
		}
		if hidden {
			fmt.Fprintln(c.out)
		}
		return r.s, r.err
	}
}

// ReadLine prompts and reads a visible line.
func (c *Console) ReadLine(ctx context.Context, prompt string) (string, error) {
	return c.read(ctx, prompt, false)
}

// ReadSecret prompts and reads a line without echo (when the input is a terminal).
func (c *Console) ReadSecret(ctx context.Context, prompt string) (string, error) {
	return c.read(ctx, prompt, true)
}

// ShowSecret prints a revealed value on the console (the broker's own terminal).
func (c *Console) ShowSecret(_ context.Context, name, value string) error {
	_, err := fmt.Fprintf(c.out, "\n[KeyGate reveal] %s = %s\n", name, value)
	return err
}

// Review prints a long text the user should read before approving; it never blocks.
func (c *Console) Review(_ context.Context, title, text string) error {
	_, err := fmt.Fprintf(c.out, "\n[%s]\n%s\n", title, text)
	return err
}
