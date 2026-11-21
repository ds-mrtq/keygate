package tty

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestReadLineParsing(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		err               error
	}{
		{"newline", "approve\n", "approve", nil},
		{"crlf", "yes\r\n", "yes", nil},
		{"spaces", "  fake secret  \n", "  fake secret  ", nil},
		{"empty line", "\n", "", nil},
		{"partial EOF", "tail", "tail", nil},
		{"empty EOF", "", "", io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readLine(bufio.NewReader(strings.NewReader(tc.input)))
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("got %q, %v; want %q, %v", got, err, tc.want, tc.err)
			}
		})
	}
	sentinel := errors.New("read failed")
	if got, err := readLine(bufio.NewReader(io.MultiReader(strings.NewReader("partial"), errorReader{sentinel}))); got != "" || !errors.Is(err, sentinel) {
		t.Fatalf("read failure = %q, %v", got, err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func processInput(t *testing.T, input string) (*os.File, *os.File) {
	t.Helper()
	in, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.WriteString(input); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut, oldReader := os.Stdin, os.Stderr, stdinReader
	os.Stdin, os.Stderr, stdinReader = in, out, bufio.NewReader(in)
	t.Cleanup(func() { os.Stdin, os.Stderr, stdinReader = oldIn, oldOut, oldReader; in.Close(); out.Close() })
	return in, out
}

func output(t *testing.T, f *os.File) string {
	t.Helper()
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestProcessPromptsNonTerminal(t *testing.T) {
	in, out := processInput(t, "fake-one\r\nfake-two\nvisible\n")
	if IsTerminal(in) {
		t.Fatal("regular file reported as terminal")
	}
	if got, err := ReadSecret("must not print", false); got != "" || !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("refused pipe = %q, %v", got, err)
	}
	for _, want := range []string{"fake-one", "fake-two"} {
		if got, err := ReadSecret("must not print", true); got != want || err != nil {
			t.Fatalf("pipe = %q, %v; want %q", got, err, want)
		}
	}
	if got, err := ReadLine("Approve? "); got != "visible" || err != nil {
		t.Fatalf("visible = %q, %v", got, err)
	}
	if got, err := ReadSecret("must not print", true); got != "" || !errors.Is(err, io.EOF) {
		t.Fatalf("EOF = %q, %v", got, err)
	}
	if got := output(t, out); got != "Approve? " {
		t.Fatalf("stderr = %q", got)
	}
}

type promptWriter struct {
	bytes.Buffer
	prompted chan string
}

func (w *promptWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	w.prompted <- string(p)
	return n, err
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
		var zero T
		return zero
	}
}

func consolePipe(t *testing.T, in *os.File) (*Console, *io.PipeWriter, *promptWriter) {
	t.Helper()
	r, w := io.Pipe()
	out := &promptWriter{prompted: make(chan string, 16)}
	c := NewConsole(r, in, out)
	t.Cleanup(func() {
		w.Close()
		r.Close()
		for range c.lines {
		}
	})
	return c, w, out
}

func TestConsolePrompts(t *testing.T) {
	for _, hidden := range []bool{false, true} {
		t.Run(map[bool]string{false: "visible", true: "hidden pipe fallback"}[hidden], func(t *testing.T) {
			in, _ := processInput(t, "")
			c, w, out := consolePipe(t, in)
			if c.Out() != out {
				t.Fatal("Out returned different writer")
			}
			for _, input := range []string{"yes\r\n", "\n", "  fake secret  \n"} {
				done := make(chan lineResult, 1)
				go func() {
					var s string
					var err error
					if hidden {
						s, err = c.ReadSecret(context.Background(), "Approve? ")
					} else {
						s, err = c.ReadLine(context.Background(), "Approve? ")
					}
					done <- lineResult{s, err}
				}()
				if got := receive(t, out.prompted); got != "Approve? " {
					t.Fatalf("prompt = %q", got)
				}
				if _, err := io.WriteString(w, input); err != nil {
					t.Fatal(err)
				}
				got := receive(t, done)
				if got.s != strings.TrimRight(input, "\r\n") || got.err != nil {
					t.Fatalf("result = %+v", got)
				}
				want := "Approve? "
				if hidden {
					if got := receive(t, out.prompted); got != "\n" {
						t.Fatalf("hidden suffix = %q", got)
					}
					want += "\n"
				}
				if got := out.String(); got != want {
					t.Fatalf("output = %q, want %q", got, want)
				}
				out.Reset()
			}
		})
	}
}

func TestConsoleCancellationAndNextPrompt(t *testing.T) {
	c, w, out := consolePipe(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan lineResult, 1)
	go func() { s, err := c.ReadSecret(ctx, "First? "); done <- lineResult{s, err} }()
	receive(t, out.prompted)
	cancel()
	if got := receive(t, done); got.s != "" || !errors.Is(got.err, context.Canceled) {
		t.Fatalf("cancel = %+v", got)
	}
	go func() { s, err := c.ReadLine(context.Background(), "Next? "); done <- lineResult{s, err} }()
	if got := receive(t, out.prompted); got != "Next? " {
		t.Fatalf("next prompt = %q", got)
	}
	if _, err := io.WriteString(w, "approve\n"); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, done); got.s != "approve" || got.err != nil {
		t.Fatalf("next result = %+v", got)
	}
}

func TestConsoleReadErrors(t *testing.T) {
	for _, hidden := range []bool{false, true} {
		c, w, out := consolePipe(t, nil)
		done := make(chan lineResult, 1)
		go func() { s, err := c.read(context.Background(), "Input: ", hidden); done <- lineResult{s, err} }()
		receive(t, out.prompted)
		sentinel := errors.New("broken input")
		w.CloseWithError(sentinel)
		if got := receive(t, done); got.s != "" || !errors.Is(got.err, sentinel) {
			t.Fatalf("read error = %+v", got)
		}
		if got, err := c.ReadLine(context.Background(), "Again: "); got != "" || !errors.Is(err, io.EOF) {
			t.Fatalf("closed reader = %q, %v", got, err)
		}
	}
}

func TestConsoleDropsTypeAhead(t *testing.T) {
	out := &promptWriter{prompted: make(chan string, 2)}
	c := &Console{out: out, lines: make(chan lineResult, 1)}
	c.lines <- lineResult{s: "stale approval"}
	done := make(chan lineResult, 1)
	go func() { s, err := c.ReadLine(context.Background(), "Approve? "); done <- lineResult{s, err} }()
	if got := receive(t, out.prompted); got != "Approve? " {
		t.Fatalf("prompt = %q", got)
	}
	c.lines <- lineResult{s: "fresh approval"}
	if got := receive(t, done); got.s != "fresh approval" || got.err != nil {
		t.Fatalf("result = %+v", got)
	}
}

func TestStdinConsole(t *testing.T) {
	_, out := processInput(t, "")
	c := Stdin()
	if c.in != os.Stdin || c.Out() != out {
		t.Fatal("Stdin did not use process stdin/stderr")
	}
	for range c.lines {
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestConsoleDisplay(t *testing.T) {
	var out bytes.Buffer
	c := &Console{out: &out}
	if err := c.ShowSecret(context.Background(), "demo", "fake-value"); err != nil {
		t.Fatal(err)
	}
	if err := c.Review(context.Background(), "Approval", "command details"); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "\n[KeyGate reveal] demo = fake-value\n\n[Approval]\ncommand details\n"; got != want {
		t.Fatalf("display = %q, want %q", got, want)
	}
	sentinel := errors.New("output failed")
	c.out = errorWriter{sentinel}
	if err := c.ShowSecret(context.Background(), "", ""); !errors.Is(err, sentinel) {
		t.Fatalf("reveal error = %v", err)
	}
	if err := c.Review(context.Background(), "", ""); !errors.Is(err, sentinel) {
		t.Fatalf("review error = %v", err)
	}
}
