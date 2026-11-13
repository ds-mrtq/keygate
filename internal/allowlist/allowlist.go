// Package allowlist decides whether a command line may receive a granted secret
// (DESIGN sec 9). The program is resolved ONCE by the broker to an absolute path and that path
// is what gets executed; the request may only name it (bare name or the exact resolved path).
package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

var (
	// ErrBlocked is returned for command lines that are never allowed.
	ErrBlocked = errors.New("lệnh bị chặn cố định (shell, trình thông dịch chạy mã trực tiếp hoặc tùy chọn cấm)")
	// ErrNotAllowed is returned when no allow_commands entry matches.
	ErrNotAllowed = errors.New("lệnh không nằm trong allow_commands")
)

// Shells that are ALWAYS blocked, whatever the policy says.
var shells = map[string]bool{
	"fish": true, "cmd": true, "csh": true, "tcsh": true, "busybox": true, "ash": true, "wsl": true,
	"nu": true, "env": true, "xargs": true, "nohup": true, "start": true,
}

// Shells that may run ONLY one script file pinned by policy (`<shell> path:<abs file>`).
var posixShells = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true}
var psShells = map[string]bool{"powershell": true, "pwsh": true}

func isPinnable(base string) bool {
	b := strings.ToLower(base)
	return posixShells[b] || psShells[b]
}

var interpreters = map[string]bool{
	"node": true, "nodejs": true, "perl": true, "ruby": true, "php": true, "lua": true, "deno": true,
	"bun": true, "wscript": true, "cscript": true, "osascript": true, "pypy": true, "pypy3": true,
	"py": true, "pyw": true,
}

// Programs that run scripts/commands of their own: an entry must carry argument patterns.
var scriptHosts = map[string]bool{
	"sql": true, "sqlplus": true, "sqlcl": true, "java": true, "javaw": true, "make": true,
	"git": true, "ssh": true, "scp": true, "sftp": true, "find": true, "go": true,
	"npx": true, "npm": true, "uv": true, "dotnet": true,
}

var pyVersioned = regexp.MustCompile(`^(python|pypy)[0-9.]*(w)?$`)

var (
	restrictFlag = regexp.MustCompile(`(?i)^-r(estrict)?$|^-R[0-9]`)
)

// BaseName returns the program name: no directory (both separators), no trailing ".exe".
func BaseName(p string) string {
	s := p
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 4 && strings.EqualFold(s[len(s)-4:], ".exe") {
		s = s[:len(s)-4]
	}
	return s
}

func isShell(base string) bool { return shells[strings.ToLower(base)] }

func isInterpreter(base string) bool {
	b := strings.ToLower(base)
	return interpreters[b] || pyVersioned.MatchString(b)
}

func isScriptHost(base string) bool { return scriptHosts[strings.ToLower(base)] }

// Entry is one parsed allow_commands item: `<cmd> [argpattern ...] [!exact]`.
// Tokens are separated by spaces; use "double quotes" for tokens containing spaces.
// cmd is a bare program name or an absolute path. An argpattern is a glob matched against the
// argument at the same position (`*` stops at separators, `**` crosses them); a pattern starting
// with `path:` (or `@path:`) is matched after Abs/Clean/EvalSymlinks and must be absolute.
// `!exact` forbids any argument beyond the patterns.
type Entry struct {
	Raw   string
	Cmd   string
	Args  []string
	Exact bool
	// Pins maps an Args index (a non-glob path: pattern) to the required `sha256:<hex>` of that file.
	Pins map[int]string
	// ProgPin pins the content of the program itself (token right after an absolute program path).
	ProgPin string
}

// HasContentPin reports whether the entry pins the script (first arg) or the program by hash.
func (e Entry) HasContentPin() bool {
	if e.ProgPin != "" {
		return true
	}
	_, ok := e.Pins[0]
	return ok
}

var sha256Tok = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// MaxPinnedFile caps the size of a hash-pinned file.
const MaxPinnedFile = 16 << 20

// FileHash returns "sha256:<hex>" of a regular, non-symlink file (read once, size capped).
func FileHash(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("không phải file thường (symlink/thư mục không được ghim)")
	}
	if st.Size() > MaxPinnedFile {
		return "", fmt.Errorf("file lớn hơn %d MiB", MaxPinnedFile>>20)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxPinnedFile+1))
	if err != nil {
		return "", err
	}
	if len(b) > MaxPinnedFile {
		return "", fmt.Errorf("file lớn hơn %d MiB", MaxPinnedFile>>20)
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// verifyPins checks the content hashes pinned by the entry against the files about to run.
// args are the canonical arguments (see canonArgs); the returned list is what LockPins re-checks.
func verifyPins(e Resolved, args []string) ([]PinFile, error) {
	var files []PinFile
	chk := func(what, path, want string) error {
		got, err := FileHash(path)
		if err != nil {
			return fmt.Errorf("%w: không ghim được %s: %v", ErrBlocked, what, err)
		}
		if got != want {
			return fmt.Errorf("%w: nội dung %s đã đổi so với hash ghim trong policy (hash hiện tại %s, policy ghi %s)", ErrBlocked, what, got, want)
		}
		files = append(files, PinFile{Path: path, Hash: want, What: what})
		return nil
	}
	if e.ProgPin != "" {
		if err := chk("chương trình "+filepath.Base(e.Path), e.Path, e.ProgPin); err != nil {
			return nil, err
		}
	}
	idx := make([]int, 0, len(e.Pins))
	for i := range e.Pins {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		if i >= len(args) {
			return nil, ErrNotAllowed
		}
		a := strings.TrimPrefix(args[i], "@")
		if err := chk("script "+filepath.Base(a), a, e.Pins[i]); err != nil {
			return nil, err
		}
	}
	return files, nil
}

// ParseEntry parses and validates an allow_commands item.
func ParseEntry(s string) (Entry, error) {
	toks, err := tokenize(s)
	if err != nil {
		return Entry{}, fmt.Errorf("allow_commands %q: %w", s, err)
	}
	if len(toks) == 0 {
		return Entry{}, fmt.Errorf("allow_commands %q: rỗng", s)
	}
	e := Entry{Raw: s, Cmd: toks[0]}
	for _, t := range toks[1:] {
		if t == "!exact" {
			e.Exact = true
			continue
		}
		if strings.HasPrefix(t, "sha256:") {
			if !sha256Tok.MatchString(t) {
				return Entry{}, fmt.Errorf("allow_commands %q: hash phải là sha256:<64 ký tự hex thường>", s)
			}
			if len(e.Args) == 0 {
				if !filepath.IsAbs(e.Cmd) {
					return Entry{}, fmt.Errorf("allow_commands %q: ghim hash chương trình cần đường dẫn chương trình tuyệt đối", s)
				}
				e.ProgPin = t
				continue
			}
			last := e.Args[len(e.Args)-1]
			if !strings.HasPrefix(strings.TrimPrefix(last, "@"), "path:") || strings.ContainsAny(last, "*?[") {
				return Entry{}, fmt.Errorf("allow_commands %q: sha256 chỉ đặt ngay sau mẫu path: trỏ đúng một file (không glob)", s)
			}
			if e.Pins == nil {
				e.Pins = map[int]string{}
			}
			e.Pins[len(e.Args)-1] = t
			continue
		}
		e.Args = append(e.Args, t)
	}
	if strings.ContainsAny(e.Cmd, `/\`) && !filepath.IsAbs(e.Cmd) {
		return Entry{}, fmt.Errorf("allow_commands %q: đường dẫn chương trình phải tuyệt đối", s)
	}
	if strings.ContainsAny(e.Cmd, "*?") {
		return Entry{}, fmt.Errorf("allow_commands %q: tên chương trình không được chứa glob", s)
	}
	base := BaseName(e.Cmd)
	if isShell(base) {
		return Entry{}, fmt.Errorf("allow_commands %q: %s là shell, luôn bị chặn", s, base)
	}
	if isPinnable(base) {
		if len(e.Args) == 0 || !strings.HasPrefix(e.Args[0], "path:") {
			return Entry{}, fmt.Errorf("allow_commands %q: shell %s chỉ được phép khi mẫu tham số đầu tiên là path:<đường dẫn tuyệt đối của đúng một file script>", s, base)
		}
		g := strings.TrimPrefix(e.Args[0], "path:")
		if strings.ContainsAny(g, "*?[") {
			return Entry{}, fmt.Errorf("allow_commands %q: đường dẫn script của shell không được chứa glob (* ? [), phải ghim đúng một file", s)
		}
		if !filepath.IsAbs(g) && !strings.HasPrefix(g, "/") {
			return Entry{}, fmt.Errorf("allow_commands %q: đường dẫn script phải tuyệt đối", s)
		}
	}
	for _, p := range e.Args {
		pp := strings.TrimPrefix(p, "@")
		if strings.HasPrefix(pp, "path:") {
			g := strings.TrimPrefix(pp, "path:")
			if !filepath.IsAbs(g) && !strings.HasPrefix(g, "/") {
				return Entry{}, fmt.Errorf("allow_commands %q: mẫu path: phải là đường dẫn tuyệt đối", s)
			}
			if hasDotDot(g) {
				return Entry{}, fmt.Errorf("allow_commands %q: mẫu không được chứa ..", s)
			}
		}
	}
	if (isScriptHost(base) || isInterpreter(base)) && len(e.Args) == 0 {
		return Entry{}, fmt.Errorf("allow_commands %q: %s cần ít nhất một mẫu tham số (script host/trình thông dịch)", s, base)
	}
	return e, nil
}

func tokenize(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQ, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			has = true
		case r == ' ' && !inQ:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if inQ {
		return nil, errors.New("dấu nháy chưa đóng")
	}
	if has {
		out = append(out, cur.String())
	}
	return out, nil
}

// Resolved is an Entry bound to the absolute program path the broker resolved for it.
type Resolved struct {
	Entry
	Path string
}

// ResolveProgram returns the absolute, symlink-free path for a bare name (via PATH) or absolute path.
func ResolveProgram(cmd string) (string, error) {
	p := cmd
	if !filepath.IsAbs(p) {
		lp, err := exec.LookPath(cmd)
		if err != nil {
			return "", fmt.Errorf("không tìm thấy chương trình %q trên PATH của broker", cmd)
		}
		p = lp
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	} else if _, serr := os.Stat(abs); serr != nil {
		return "", fmt.Errorf("không thấy chương trình %q: %v", cmd, serr)
	}
	return abs, nil
}

// Resolve binds entries to program paths. Entries whose program cannot be found are kept with an
// empty Path (they never match) so a missing optional tool does not disable the whole policy.
func Resolve(entries []Entry) []Resolved {
	out := make([]Resolved, 0, len(entries))
	for _, e := range entries {
		p, _ := ResolveProgram(e.Cmd)
		out = append(out, Resolved{Entry: e, Path: p})
	}
	return out
}

// Match is the outcome of Check: what to execute.
type Match struct {
	Entry Entry
	Path  string    // absolute program to execute
	Argv  []string  // argv to execute: Path, injected options, then the request arguments (path: args canonical)
	Pins  []PinFile // hash-pinned files; call LockPins right before running
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func canon(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}

func nameMatches(entryCmd, reqName string) bool {
	want := BaseName(entryCmd)
	got := reqName
	if runtime.GOOS == "windows" {
		got = BaseName(reqName)
	}
	return strings.EqualFold(want, got)
}

func hasDotDot(s string) bool {
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

// Check finds the entry that allows argv (run from dir) or returns ErrBlocked/ErrNotAllowed.
func Check(entries []Resolved, argv []string, dir string) (*Match, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("lệnh rỗng")
	}
	req0 := argv[0]
	if isShell(BaseName(req0)) && !isPinnable(BaseName(req0)) {
		return nil, fmt.Errorf("%w: shell %q", ErrBlocked, BaseName(req0))
	}
	hasSep := strings.ContainsAny(req0, `/\`)
	if dir == "" {
		dir = "."
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	var reqPath string
	if hasSep {
		reqPath = canon(req0)
	}
	var firstErr error
	for _, e := range entries {
		if e.Path == "" {
			continue
		}
		if hasSep {
			if !samePath(reqPath, e.Path) {
				continue
			}
		} else if !nameMatches(e.Cmd, req0) {
			continue
		}
		m, err := checkEntry(e, argv, dir)
		if err == nil {
			return m, nil
		}
		if firstErr == nil || errors.Is(err, ErrBlocked) {
			firstErr = err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if hasSep {
		return nil, fmt.Errorf("%w: %q có dấu phân cách; chỉ được dùng tên chương trình hoặc đúng đường dẫn đã phân giải", ErrNotAllowed, req0)
	}
	return nil, ErrNotAllowed
}

func checkEntry(e Resolved, argv []string, dir string) (*Match, error) {
	base := BaseName(e.Path)
	if isShell(base) {
		return nil, fmt.Errorf("%w: shell %q", ErrBlocked, base)
	}
	args := argv[1:]
	pats := e.Args
	if isPinnable(base) {
		return checkShell(e, argv, dir)
	}
	if len(args) < len(pats) || (e.Exact && len(args) != len(pats)) {
		return nil, ErrNotAllowed
	}
	if isInterpreter(base) {
		if len(args) == 0 {
			return nil, ErrNotAllowed
		}
		if strings.HasPrefix(args[0], "-") {
			return nil, fmt.Errorf("%w: %s không cho tùy chọn trước đường dẫn script", ErrBlocked, base)
		}
	}
	for i, p := range pats {
		if !matchArg(p, args[i], dir) {
			return nil, ErrNotAllowed
		}
	}
	cargs := canonArgs(pats, args, dir)
	pins, err := verifyPins(e, cargs)
	if err != nil {
		return nil, err
	}
	m := &Match{Entry: e.Entry, Path: e.Path, Pins: pins}
	m.Argv = append(m.Argv, e.Path)
	lb := strings.ToLower(base)
	if lb == "sql" || lb == "sqlcl" || lb == "sqlplus" {
		for _, a := range args {
			if restrictFlag.MatchString(a) {
				return nil, fmt.Errorf("%w: không được đổi chế độ hạn chế (-R)", ErrBlocked)
			}
		}
		lvl := "4" // SQLcl: blocks host, !, script, spool, nested @ (see docs/DESIGN-notes-sqlcl.md)
		if lb == "sqlplus" {
			lvl = "3"
		}
		m.Argv = append(m.Argv, "-R", lvl)
	}
	m.Argv = append(m.Argv, cargs...)
	return m, nil
}

// checkShell allows a pinnable shell only for the exact script file pinned in the entry.
func checkShell(e Resolved, argv []string, dir string) (*Match, error) {
	base := strings.ToLower(BaseName(e.Path))
	args := argv[1:]
	if len(args) == 0 || len(e.Args) == 0 {
		return nil, ErrNotAllowed
	}
	if strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[0], "/") && len(args[0]) == 2 || strings.HasPrefix(args[0], "+") {
		return nil, fmt.Errorf("%w: %s không cho tùy chọn trước script đã ghim", ErrBlocked, base)
	}
	for _, a := range args {
		switch a {
		case "-c", "-s", "-i", "--init-file", "--rcfile", "-o", "+o":
			if posixShells[base] {
				return nil, fmt.Errorf("%w: %s %s bị cấm", ErrBlocked, base, a)
			}
		}
	}
	pinned := strings.TrimPrefix(e.Args[0], "path:")
	pinnedC := canon(pinned)
	a0 := args[0]
	if hasDotDot(a0) {
		return nil, ErrNotAllowed
	}
	if !filepath.IsAbs(a0) {
		a0 = filepath.Join(dir, a0)
	}
	if !samePath(canon(a0), pinnedC) {
		return nil, ErrNotAllowed
	}
	st, err := os.Lstat(pinned)
	if err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: script ghim phải là file thường (không phải symlink/thư mục)", ErrBlocked)
	}
	cargs := canonArgs(e.Args, args, dir)
	cargs[0] = pinnedC
	pins, err := verifyPins(e, cargs)
	if err != nil {
		return nil, err
	}
	rest := args[1:]
	for i, p := range e.Args[1:] {
		if i >= len(rest) || !matchArg(p, rest[i], dir) {
			return nil, ErrNotAllowed
		}
	}
	if e.Exact && len(rest) != len(e.Args)-1 {
		return nil, ErrNotAllowed
	}
	m := &Match{Entry: e.Entry, Path: e.Path, Argv: []string{e.Path}, Pins: pins}
	switch {
	case psShells[base]:
		m.Argv = append(m.Argv, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", pinnedC)
	case base == "bash":
		m.Argv = append(m.Argv, "--noprofile", "--norc", pinnedC)
	default:
		m.Argv = append(m.Argv, pinnedC)
	}
	m.Argv = append(m.Argv, cargs[1:]...)
	return m, nil
}

func matchArg(pat, arg, dir string) bool {
	prefix := ""
	p := pat
	if strings.HasPrefix(p, "@") {
		prefix, p = "@", p[1:]
	}
	if strings.HasPrefix(p, "path:") {
		g := filepath.ToSlash(strings.TrimPrefix(p, "path:"))
		a := arg
		if prefix != "" {
			if !strings.HasPrefix(a, prefix) {
				return false
			}
			a = a[len(prefix):]
		}
		if hasDotDot(a) {
			return false
		}
		if !filepath.IsAbs(a) {
			a = filepath.Join(dir, a)
		}
		return GlobPath(filepath.ToSlash(filepath.Clean(g)), filepath.ToSlash(canon(a)))
	}
	if strings.ContainsAny(pat, "*?") && hasDotDot(arg) {
		return false
	}
	return GlobPath(pat, arg)
}

// GlobPath matches s against pattern with path semantics: '*' and '?' never cross a separator,
// '**' does. Backslash and slash compare equal; comparison is case-insensitive on Windows.
func GlobPath(pattern, s string) bool {
	p := strings.ReplaceAll(pattern, `\`, "/")
	t := strings.ReplaceAll(s, `\`, "/")
	if runtime.GOOS == "windows" {
		p, t = strings.ToLower(p), strings.ToLower(t)
	}
	return globPath(p, t)
}

func globPath(p, s string) bool {
	for len(p) > 0 {
		switch {
		case strings.HasPrefix(p, "**"):
			rest := strings.TrimLeft(p, "*")
			for i := 0; i <= len(s); i++ {
				if globPath(rest, s[i:]) {
					return true
				}
				// "**/" also matches zero directories
				if strings.HasPrefix(rest, "/") && globPath(rest[1:], s[i:]) {
					return true
				}
			}
			return false
		case p[0] == '*':
			for i := 0; i <= len(s); i++ {
				if globPath(p[1:], s[i:]) {
					return true
				}
				if i < len(s) && s[i] == '/' {
					break
				}
			}
			return false
		case p[0] == '?':
			if s == "" || s[0] == '/' {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			if s == "" || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return s == ""
}

// Glob matches s against pattern: '*' = any run of characters (including separators),
// '?' = any single character. Used for secret names, not for paths.
func Glob(pattern, s string) bool {
	p := []rune(pattern)
	t := []rune(s)
	pi, ti := 0, 0
	star, mark := -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
