// Package execwrap builds the temporary environment (env vars, 0600 files, Oracle wallet)
// for a child process, runs it as a killable process tree and cleans everything up
// (DESIGN sec 10).
package execwrap

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"keygate/internal/envname"
)

// Secret is a decrypted item handed to the wrapper. Never log or print Value.
type Secret struct {
	Name     string
	Value    string
	Kind     string // env|file|oracle-wallet|template
	EnvName  string
	TNSAlias string
	User     string
	FileExt  string
}

// Config carries the tool paths (from the pinned policy `oracle:` block; empty = discover) and
// where temp material lives.
type Config struct {
	Java     string
	PkiJar   string
	TNSAdmin string
	// RunDir is the private directory (KG_HOME/run) for plaintext temp material; empty = os.TempDir (tests).
	RunDir string
}

// DefaultMaxRuntime bounds a child when RunOpts.MaxRuntime is zero.
const DefaultMaxRuntime = 30 * time.Minute

// waitDelay is how long Wait lingers on output pipes held open by grandchildren.
const waitDelay = 3 * time.Second

// Env is the prepared environment of one run. Call Cleanup when done (idempotent).
type Env struct {
	vars   []string
	dirs   []string
	runDir string
	mu     sync.Mutex
}

var (
	regMu    sync.Mutex
	registry = map[*Env]struct{}{}
)

// CleanupAll removes the temp material of every live Env (for broker shutdown / signals).
func CleanupAll() {
	regMu.Lock()
	envs := make([]*Env, 0, len(registry))
	for e := range registry {
		envs = append(envs, e)
	}
	regMu.Unlock()
	for _, e := range envs {
		e.Cleanup()
	}
}

// Sweep removes everything left under runDir by a crashed broker (call at broker start).
func Sweep(runDir string) error {
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	ents, err := os.ReadDir(runDir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		shredTree(filepath.Join(runDir, e.Name()))
	}
	return nil
}

// shredTree overwrites regular files with zeros, then removes the tree.
func shredTree(root string) {
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if st, err := d.Info(); err == nil && st.Mode().IsRegular() {
			if w, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
				w.Write(make([]byte, st.Size()))
				w.Sync()
				w.Close()
			}
		}
		return nil
	})
	os.RemoveAll(root)
}

var nonIdent = regexp.MustCompile(`[^A-Za-z0-9]+`)

// EnvVarName derives the default variable suffix: upper-case, non-alphanumerics -> "_".
func EnvVarName(secretName string) string {
	return strings.ToUpper(strings.Trim(nonIdent.ReplaceAllString(secretName, "_"), "_"))
}

// effectiveKind maps (as override, item kind) to env|file|oracle-wallet.
func effectiveKind(as, kind string) (string, error) {
	switch as {
	case "env":
		return "env", nil
	case "file":
		return "file", nil
	case "wallet":
		return "oracle-wallet", nil
	case "":
		switch kind {
		case "", "env", "template":
			return "env", nil
		case "file", "oracle-wallet":
			return kind, nil
		}
		return "", fmt.Errorf("kind %q không hỗ trợ", kind)
	}
	return "", fmt.Errorf("--as %q không hợp lệ (env|file|wallet)", as)
}

var safeExt = regexp.MustCompile(`^[A-Za-z0-9]{1,10}$`)

func (c Config) mkTemp(pattern string) (string, error) {
	base := c.RunDir
	if base != "" {
		if err := os.MkdirAll(base, 0o700); err != nil {
			return "", err
		}
	}
	return os.MkdirTemp(base, pattern)
}

// NewEnv materializes secrets per kind (or the as override: env|file|wallet).
func NewEnv(ctx context.Context, cfg Config, secrets []Secret, as string) (_ *Env, err error) {
	env := &Env{runDir: cfg.RunDir}
	regMu.Lock()
	registry[env] = struct{}{}
	regMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			env.Cleanup()
			panic(r)
		}
		if err != nil {
			env.Cleanup()
		}
	}()
	var wallets []Secret
	for _, s := range secrets {
		k, err := effectiveKind(as, s.Kind)
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", s.Name, err)
		}
		switch k {
		case "env":
			name := s.EnvName
			if name == "" {
				name = "KG_" + EnvVarName(s.Name)
			} else if err := envname.Check(name); err != nil {
				return nil, fmt.Errorf("secret %q: %w", s.Name, err)
			}
			env.vars = append(env.vars, name+"="+s.Value)
		case "file":
			p, err := env.writeTemp(cfg, []byte(s.Value), s.FileExt)
			if err != nil {
				return nil, err
			}
			name := s.EnvName
			if name == "" {
				name = "KG_FILE_" + EnvVarName(s.Name)
			} else if err := envname.Check(name); err != nil {
				return nil, fmt.Errorf("secret %q: %w", s.Name, err)
			}
			env.vars = append(env.vars, name+"="+p)
		case "oracle-wallet":
			if s.User == "" || s.TNSAlias == "" {
				return nil, fmt.Errorf("secret %q: oracle-wallet cần user và tns_alias", s.Name)
			}
			wallets = append(wallets, s)
		}
	}
	if len(wallets) > 0 {
		dir, err := env.makeWallet(ctx, cfg, wallets)
		if err != nil {
			return nil, err
		}
		env.vars = append(env.vars, "TNS_ADMIN="+dir)
	}
	return env, nil
}

// AddFile writes content to a new 0600 temp file and exposes its path as envVar.
func (e *Env) AddFile(cfg Config, envVar string, content []byte, ext string) (string, error) {
	if err := envname.Check(envVar); err != nil {
		return "", err
	}
	p, err := e.writeTemp(cfg, content, ext)
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	e.vars = append(e.vars, envVar+"="+p)
	e.mu.Unlock()
	return p, nil
}

func (e *Env) writeTemp(cfg Config, content []byte, ext string) (string, error) {
	dir, err := cfg.mkTemp("kg-file-")
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	e.dirs = append(e.dirs, dir)
	e.mu.Unlock()
	name := "secret"
	if ext = strings.TrimPrefix(ext, "."); safeExt.MatchString(ext) {
		name += "." + ext
	}
	p := filepath.Join(dir, name)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return "", err
	}
	return p, f.Close()
}

// Vars returns the KEY=VALUE pairs the wrapper adds (do not print: contains values).
func (e *Env) Vars() []string { return append([]string(nil), e.vars...) }

// Environ merges base with the wrapper variables (wrapper wins).
func (e *Env) Environ(base []string) []string {
	over := map[string]bool{}
	for _, v := range e.vars {
		k, _, _ := strings.Cut(v, "=")
		over[normKey(k)] = true
	}
	out := make([]string, 0, len(base)+len(e.vars))
	for _, b := range base {
		k, _, _ := strings.Cut(b, "=")
		if nk := normKey(k); !over[nk] && nk != normKey("BASH_ENV") && nk != normKey("ENV") {
			out = append(out, b)
		}
	}
	return append(out, e.vars...)
}

func normKey(k string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(k)
	}
	return k
}

// Cleanup overwrites every temp file and removes every temp directory. Safe to call repeatedly.
func (e *Env) Cleanup() {
	e.mu.Lock()
	dirs := e.dirs
	e.dirs, e.vars = nil, nil
	e.mu.Unlock()
	for _, d := range dirs {
		shredTree(d)
	}
	regMu.Lock()
	delete(registry, e)
	regMu.Unlock()
}

// RunOpts describes the child process.
type RunOpts struct {
	Argv           []string
	Dir            string
	Stdin          io.Reader
	Stdout, Stderr io.Writer // pass the same writer for one ordered stream; wrap with a redactor
	MaxRuntime     time.Duration
}

// ErrMaxRuntime is returned when the child exceeded its maximum runtime and was killed.
var ErrMaxRuntime = errors.New("lệnh vượt quá thời gian chạy tối đa, đã bị diệt")

// Run executes the child with the wrapper environment as a process tree that is killed as a whole
// on cancel, signal (SIGINT/SIGTERM), timeout or broker exit. Returns the exit code; error only
// when the process could not be started, was killed by timeout/cancel, or could not be waited for.
func (e *Env) Run(ctx context.Context, o RunOpts) (int, error) {
	if len(o.Argv) == 0 {
		return -1, errors.New("lệnh rỗng")
	}
	max := o.MaxRuntime
	if max <= 0 {
		max = DefaultMaxRuntime
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, max)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.Argv[0], o.Argv[1:]...)
	cmd.Dir = o.Dir
	cmd.Env = e.Environ(os.Environ())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = o.Stdin, o.Stdout, o.Stderr
	if o.Stdin == nil {
		// Java console tools (SQLcl) call available() on stdin; on Windows that fails with
		// "Incorrect function" for the NUL device. An empty regular file behaves like EOF.
		empty, err := emptyStdin()
		if err != nil {
			return -1, err
		}
		defer os.Remove(empty.Name())
		defer empty.Close()
		cmd.Stdin = empty
	}
	cmd.WaitDelay = waitDelay
	tr := newTree()
	defer tr.close()
	tr.configure(cmd)
	cmd.Cancel = func() error {
		tr.kill()
		return cmd.Process.Kill()
	}
	if err := cmd.Start(); err != nil {
		return -1, err
	}
	if err := tr.attach(cmd); err != nil {
		tr.kill()
		cmd.Process.Kill()
		cmd.Wait()
		return -1, fmt.Errorf("không gắn được tiến trình vào nhóm diệt: %w", err)
	}
	err := cmd.Wait()
	tr.kill() // stragglers (grandchildren) must not outlive the run
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return -1, ErrMaxRuntime
	}
	var ee *exec.ExitError
	switch {
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
		return 0, nil
	case errors.As(err, &ee):
		if ctx.Err() != nil {
			return ee.ExitCode(), ctx.Err()
		}
		return ee.ExitCode(), nil
	}
	return -1, err
}

// emptyStdin returns an open, empty regular file to use as a child's stdin.
func emptyStdin() (*os.File, error) {
	return os.CreateTemp("", "kg-stdin-*")
}

// Run is NewEnv + Env.Run + Cleanup (also on panic).
func Run(ctx context.Context, cfg Config, secrets []Secret, as string, o RunOpts) (int, error) {
	env, err := NewEnv(ctx, cfg, secrets, as)
	if err != nil {
		return -1, err
	}
	defer env.Cleanup()
	return env.Run(ctx, o)
}

const walletAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// RandomPassword returns n random alphanumerics with at least one upper, lower and digit.
func RandomPassword(n int) (string, error) {
	if n < 8 {
		n = 8
	}
	for {
		b := make([]byte, n)
		var up, lo, dg bool
		for i := range b {
			x, err := rand.Int(rand.Reader, big.NewInt(int64(len(walletAlphabet))))
			if err != nil {
				return "", err
			}
			c := walletAlphabet[x.Int64()]
			b[i] = c
			switch {
			case c >= 'A' && c <= 'Z':
				up = true
			case c >= 'a' && c <= 'z':
				lo = true
			default:
				dg = true
			}
		}
		if up && lo && dg {
			return string(b), nil
		}
	}
}
