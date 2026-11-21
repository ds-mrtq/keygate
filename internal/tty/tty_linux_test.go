package tty

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

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
