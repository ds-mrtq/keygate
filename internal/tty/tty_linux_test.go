package tty

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

func terminalMode(t *testing.T, f *os.File) *unix.Termios {
	t.Helper()
	m, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDisableEcho(t *testing.T) {
	_, slave := openPTY(t)
	if !IsTerminal(slave) {
		t.Fatal("PTY not detected as terminal")
	}
	before := terminalMode(t, slave)
	if before.Lflag&unix.ECHO == 0 {
		t.Fatal("PTY must begin with echo enabled")
	}
	restore, err := disableEcho(slave)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	want := *before
	want.Lflag &^= unix.ECHO
	if got := terminalMode(t, slave); !reflect.DeepEqual(*got, want) {
		t.Fatalf("disabled mode = %+v; want %+v", got, want)
	}
	restore()
	if got := terminalMode(t, slave); !reflect.DeepEqual(got, before) {
		t.Fatalf("restored mode = %+v; want %+v", got, before)
	}
	file, _ := processInput(t, "")
	if restore, err := disableEcho(file); err == nil || restore != nil {
		t.Fatalf("non-terminal disable = %v, restore nil = %v", err, restore == nil)
	}
}

func TestReadSecretTerminal(t *testing.T) {
	master, slave := openPTY(t)
	_, out := processInput(t, "")
	os.Stdin, stdinReader = slave, bufio.NewReader(slave)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	os.Stderr = w
	before := terminalMode(t, slave)
	done := make(chan lineResult, 1)
	go func() { s, err := ReadSecret("Password: ", false); done <- lineResult{s, err} }()
	prompt := make(chan string, 1)
	go func() {
		b := make([]byte, len("Password: "))
		_, err := io.ReadFull(r, b)
		if err != nil {
			prompt <- err.Error()
			return
		}
		prompt <- string(b)
	}()
	if got := receive(t, prompt); got != "Password: " {
		t.Fatalf("prompt = %q", got)
	}
	if terminalMode(t, slave).Lflag&unix.ECHO != 0 {
		t.Fatal("password prompt left echo enabled")
	}
	if _, err := io.WriteString(master, "fake-password\n"); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, done); got.s != "fake-password" || got.err != nil {
		t.Fatalf("password = %+v", got)
	}
	if got := terminalMode(t, slave); !reflect.DeepEqual(got, before) {
		t.Fatalf("mode not restored: %+v", got)
	}
	w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "\n" {
		t.Fatalf("password output = %q", b)
	}
	if got := output(t, out); got != "" {
		t.Fatalf("unexpected output = %q", got)
	}
}

func TestConsoleTerminalEchoRestored(t *testing.T) {
	for _, cancelPrompt := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancelPrompt), func(t *testing.T) {
			_, slave := openPTY(t)
			before := terminalMode(t, slave)
			c, w, out := consolePipe(t, slave)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan lineResult, 1)
			go func() { s, err := c.ReadSecret(ctx, "Secret: "); done <- lineResult{s, err} }()
			if got := receive(t, out.prompted); got != "Secret: " {
				t.Fatalf("prompt = %q", got)
			}
			if terminalMode(t, slave).Lflag&unix.ECHO != 0 {
				t.Fatal("echo enabled during hidden prompt")
			}
			if cancelPrompt {
				cancel()
			} else if _, err := io.WriteString(w, "fake-value\n"); err != nil {
				t.Fatal(err)
			}
			got := receive(t, done)
			if cancelPrompt {
				if got.err != context.Canceled {
					t.Fatalf("cancel error = %v", got.err)
				}
			} else if got.s != "fake-value" || got.err != nil {
				t.Fatalf("result = %+v", got)
			}
			if got := terminalMode(t, slave); !reflect.DeepEqual(got, before) {
				t.Fatalf("mode not restored: %+v", got)
			}
		})
	}
}

// typeAfter types answer on the PTY master once want has been printed on it.
func typeAfter(t *testing.T, master *os.File, want, answer string) {
	t.Helper()
	go func() {
		var seen []byte
		buf := make([]byte, 256)
		for {
			n, err := master.Read(buf)
			seen = append(seen, buf[:n]...)
			if bytes.Contains(seen, []byte(want)) {
				master.WriteString(answer + "\n")
				return
			}
			if err != nil {
				return
			}
		}
	}()
}

func noControllingTerminal() (*os.File, error) { return nil, errors.New("no controlling terminal") }

func TestReadTerminalSecretFromStdinTTY(t *testing.T) {
	master, slave := openPTY(t)
	c := NewConsole(slave, slave, slave)
	c.SetControllingTerminal(noControllingTerminal)
	typeAfter(t, master, "pw? ", "typed-at-tty")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := c.ReadTerminalSecret(ctx, "pw? ")
	if err != nil || got != "typed-at-tty" {
		t.Fatalf("ReadTerminalSecret = %q, %v; want the line typed at the TTY", got, err)
	}
}

func TestReadTerminalSecretRefusesPipeAndFile(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	w.WriteString("from-a-pipe\n")
	file := filepath.Join(t.TempDir(), "pw.txt")
	if err := os.WriteFile(file, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for name, in := range map[string]*os.File{"pipe": r, "file": f} {
		c := NewConsole(in, in, io.Discard)
		c.SetControllingTerminal(noControllingTerminal)
		if got, err := c.ReadTerminalSecret(context.Background(), "pw? "); !errors.Is(err, ErrNoTerminal) || got != "" {
			t.Fatalf("%s: ReadTerminalSecret = %q, %v; want ErrNoTerminal", name, got, err)
		}
	}
}

func TestReadTerminalSecretFromControllingTerminal(t *testing.T) {
	master, slave := openPTY(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	w.WriteString("from-a-pipe\n")
	c := NewConsole(r, r, io.Discard)
	c.SetControllingTerminal(func() (*os.File, error) { return os.OpenFile(slave.Name(), os.O_RDWR|unix.O_NOCTTY, 0) })
	typeAfter(t, master, "pw? ", "typed-at-ctty")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := c.ReadTerminalSecret(ctx, "pw? ")
	if err != nil || got != "typed-at-ctty" {
		t.Fatalf("ReadTerminalSecret = %q, %v; want the line typed at the controlling terminal, never the pipe", got, err)
	}
}

func TestReadTerminalSecretControllingTerminalCancel(t *testing.T) {
	master, slave := openPTY(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	c := NewConsole(r, r, io.Discard)
	c.SetControllingTerminal(func() (*os.File, error) { return os.OpenFile(slave.Name(), os.O_RDWR|unix.O_NOCTTY, 0) })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.ReadTerminalSecret(ctx, "pw? "); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadTerminalSecret = %v; want the deadline", err)
	}
	if m := terminalMode(t, slave); m.Lflag&unix.ECHO == 0 {
		t.Fatal("echo not restored after a cancelled prompt")
	}
	// The expired prompt must not leave a reader behind that takes the next answer.
	go func() {
		time.Sleep(100 * time.Millisecond)
		master.Write([]byte("next-answer\n"))
	}()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if got, err := c.ReadTerminalSecret(ctx2, "pw again? "); err != nil || got != "next-answer" {
		t.Fatalf("second ReadTerminalSecret = %q, %v; want the next line typed", got, err)
	}
}
