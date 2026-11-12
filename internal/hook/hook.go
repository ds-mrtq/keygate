// Package hook implements the PreToolUse check used by `kg hook check`.
// It blocks agent tool calls that would read secret material or put
// passwords on a command line. It never logs or echoes the offending text.
//
// The hook is a speed bump, not a security boundary: an agent running as the
// same OS user can always find another way. The broker is the real control.
package hook

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
)

const hint = " Dùng `kg run --secret <tên> -- <lệnh>` để chạy lệnh với secret được tiêm sẵn; agent không cần và không được thấy giá trị."

const (
	msgHome   = "Chặn: truy cập thư mục kho khóa KeyGate (KG_HOME, run/, broker.sock, file tạm kg-*)." + hint
	msgFile   = "Chặn: đụng tới file chứa secret (.env / *.env / *.sso / *.p12 / cwallet*)." + hint
	msgEnv    = "Chặn: lệnh liệt kê/đọc biến môi trường (có thể lộ secret)." + hint
	msgGrep   = "Chặn: tìm đệ quy các từ khóa secret (PASSWORD/SECRET/TOKEN) trên cả thư mục." + hint
	msgReveal = "Chặn: `kg reveal` chỉ dành cho người dùng gõ trong terminal của chính họ." + hint
)

// pathKeys are tool-input fields that hold file paths or globs.
var pathKeys = []string{"file_path", "path", "paths", "glob", "notebook_path", "file", "files", "filename", "include", "dir", "directory", "cwd"}

// Check inspects a PreToolUse payload (Claude Code or omp shape).
// blocked=true means the tool call must be refused with reason.
func Check(input []byte, kgHome string) (blocked bool, reason string, err error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(input, &m); err != nil {
		return false, "", fmt.Errorf("hook: invalid JSON: %w", err)
	}
	var tool string
	for _, k := range []string{"tool_name", "toolName"} {
		if v, ok := m[k]; ok {
			_ = json.Unmarshal(v, &tool)
		}
	}
	tool = strings.ToLower(tool)
	raw := m["tool_input"]
	if raw == nil {
		raw = m["input"]
	}
	if raw == nil {
		return false, "", nil
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return false, "", nil // non-object input: nothing we understand
	}
	strs := func(k string) []string {
		v, ok := in[k]
		if !ok {
			return nil
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			return []string{s}
		}
		var a []string
		if json.Unmarshal(v, &a) == nil {
			return a
		}
		return nil
	}
	home := normPath(kgHome)

	keys := pathKeys
	if tool == "glob" { // for the glob tool the pattern is a path; for grep it is a regex
		keys = append(append([]string{}, keys...), "pattern")
	}
	for _, k := range keys {
		for _, s := range strs(k) {
			if r := checkPath(s, home); r != "" {
				return true, r, nil
			}
		}
	}
	for _, u := range strs("url") { // WebFetch of file:// URLs
		if l := strings.ToLower(u); strings.HasPrefix(l, "file:") {
			u = strings.TrimLeft(u[len("file:"):], "/")
			if r := checkPath(u, home); r != "" {
				return true, r, nil
			}
		}
	}
	for _, cmd := range strs("command") {
		if cmd != "" {
			if r := checkCommand(cmd, home, 0); r != "" {
				return true, r, nil
			}
		}
	}
	return false, "", nil
}

func normPath(p string) string {
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"))
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}

// sensitiveBase reports whether a literal file base name is secret material.
func sensitiveBase(base string) bool {
	if i := strings.Index(base, ":"); i >= 0 { // omp read selectors, e.g. ".env:1-5"
		base = base[:i]
	}
	switch {
	case base == ".env":
		return true
	case strings.HasPrefix(base, ".env."):
		switch base[len(".env."):] {
		case "example", "sample", "template":
			return false
		}
		return true
	case strings.HasSuffix(base, ".env"):
		// prod.env etc.; but not JS/TS property access like process.env
		switch {
		case base == "process.env", strings.HasSuffix(base, "meta.env"), base == "deno.env":
			return false
		}
		return true
	case strings.HasSuffix(base, ".sso"), strings.HasSuffix(base, ".p12"):
		return true
	case strings.HasPrefix(base, "cwallet"):
		return true
	}
	return false
}

// globSamples are representative sensitive names a glob component is matched against.
var globSamples = []string{
	".env", ".env.local", ".env.production", ".env.development", "prod.env",
	"cwallet.sso", "ewallet.p12", "cert.p12",
	".keygate", "kg-file-1", "kg-wallet-1",
}

// componentHit classifies one path component: msgHome for KeyGate state,
// msgFile for secret files, "" otherwise. last is true for the final component.
func componentHit(comp string, last bool) string {
	if i := strings.Index(comp, ":"); i >= 0 {
		comp = comp[:i]
	}
	if comp == "" {
		return ""
	}
	if comp == ".keygate" || strings.HasPrefix(comp, "kg-file-") || strings.HasPrefix(comp, "kg-wallet-") {
		return msgHome
	}
	if last && sensitiveBase(comp) {
		return msgFile
	}
	if strings.ContainsAny(comp, "*?[") {
		lit := 0
		for _, c := range comp {
			if !strings.ContainsRune("*?[]", c) {
				lit++
			}
		}
		if lit < 2 { // "*", "*.*", ".*" are too common to treat as secret globs
			return ""
		}
		for _, s := range globSamples {
			if ok, _ := path.Match(comp, s); ok {
				if s == ".keygate" || strings.HasPrefix(s, "kg-") {
					return msgHome
				}
				return msgFile
			}
		}
	}
	return ""
}

// checkPath checks a path or glob; ";" separates several paths (omp multi-path).
func checkPath(p, home string) string {
	for _, part := range strings.Split(p, ";") {
		if r := checkOne(part, home); r != "" {
			return r
		}
	}
	return ""
}

func checkOne(p, home string) string {
	n := normPath(p)
	if n == "" {
		return ""
	}
	if home != "" && (n == home || strings.HasPrefix(n, home+"/")) {
		return msgHome
	}
	comps := strings.Split(n, "/")
	for i, c := range comps {
		if r := componentHit(c, i == len(comps)-1); r != "" {
			return r
		}
	}
	return ""
}

var tokenSplit = regexp.MustCompile("[\\s\"'`;|&<>()=,]+")

var (
	reEnvDumpWin = regexp.MustCompile(`(?i)\b(?:get-childitem|gci|ls|dir|get-item|gi)\s+(?:-path\s+)?["']?env:`)
	reEnvPS      = regexp.MustCompile(`(?i)\$env:(?:[^A-Za-z0-9_{]|$)`)
	reEnvNet     = regexp.MustCompile(`(?i)\[\s*(?:system\.)?environment\s*\]\s*::\s*GetEnvironmentVariables`)
	reProcEnv    = regexp.MustCompile(`/proc/[^\s/]+/environ`)
	reInterpEnv  = regexp.MustCompile(`(?is)\b(?:python[0-9.]*|py|node(?:js)?|bun|deno|perl|ruby|php|pwsh|powershell)(?:\.exe)?\b.*?(?:os\.environ|os\.getenv|process\.env|\bgetenv\b|\$_ENV|\$_SERVER|\$ENV\{|%ENV|Deno\.env|GetEnvironmentVariable)`)
	reRubyENV    = regexp.MustCompile(`(?s)\b(?:ruby|perl)(?:\.exe)?\b.*?\bENV\b`)
	reShellC     = regexp.MustCompile(`(?is)\b(?:bash|sh|zsh|dash|ksh|fish|cmd|pwsh|powershell)(?:\.exe)?\s+(?:[-/][\w-]+\s+)*?(?:-[a-zA-Z]*c|-command|/c|/k)\s+(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|(.+))`)
	reKgHomeVar  = regexp.MustCompile(`(?i)\$\{?KG_HOME\b|%KG_HOME%|\$env:KG_HOME`)
	reBrokerSock = regexp.MustCompile(`(?i)broker\.sock|\bAF_UNIX\b|\bsocat\b|--unix-socket|\b(?:nc|ncat|netcat)(?:\.exe)?\b[^|;&\n]*\s-\w*U`)
	reMacSec     = regexp.MustCompile(`(?i)\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain)`)
	reReveal     = regexp.MustCompile(`(?i)(?:^|[\s;|&("'` + "`" + `])(?:\S*[/\\])?["']?kg(?:\.exe)?["']?\s+["']?reveal\b`)
	reSecretKW   = regexp.MustCompile(`(?i)password|passwd|secret|token|api[_-]?key|credential`)
	reRedirect   = regexp.MustCompile(`^\d*[<>]`)

	reUserPass  = regexp.MustCompile(`(?:^|[\s"'=])[A-Za-z][\w$#.\-]*/[^\s/@'"]+@[A-Za-z/_][\w.\-:/]*`)
	reLongPW    = regexp.MustCompile(`(?i)(?:^|\s)--(?:password|passwd|pass)(?:=|\s+[^-\s])`)
	reDashP     = regexp.MustCompile(`(?:^|\s)-p(\S+)`)
	reSshpass   = regexp.MustCompile(`(?i)\bsshpass\s+-p`)
	reBearer    = regexp.MustCompile(`(?i)authorization:\s*bearer\s+[A-Za-z0-9._~+/=\-]{20,}`)
	rePwAssign  = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])[A-Za-z0-9_]*password\s*=\s*[^\s=]`)
	reIdentBy   = regexp.MustCompile(`(?i)\bidentified\s+by\s+\S`)
	rePortLike  = regexp.MustCompile(`^\d+(?::\d+)*(?:/\w+)?$`)
	reMySQLLike = regexp.MustCompile(`(?i)\b(?:mysql|mysqldump|mysqladmin|mariadb|mysqlimport)(?:\.exe)?\b`)
	reSegSplit  = regexp.MustCompile("[;|&\n(`]+")
)

func checkCommand(cmd, home string, depth int) string {
	// KG_HOME and secret files referenced anywhere in the command.
	n := strings.ToLower(strings.ReplaceAll(cmd, "\\", "/"))
	if home != "" && containsPath(n, home) {
		return msgHome
	}
	if reKgHomeVar.MatchString(cmd) || reBrokerSock.MatchString(cmd) || reMacSec.MatchString(cmd) {
		return msgHome
	}
	for _, tok := range tokenSplit.Split(n, -1) {
		if tok == "" {
			continue
		}
		if r := checkOne(tok, home); r != "" {
			return r
		}
	}

	if reEnvDumpWin.MatchString(cmd) || reEnvPS.MatchString(cmd) || reEnvNet.MatchString(cmd) ||
		reProcEnv.MatchString(n) || reInterpEnv.MatchString(cmd) || reRubyENV.MatchString(cmd) {
		return msgEnv
	}
	if reReveal.MatchString(cmd) {
		return msgReveal
	}
	if r := checkSegments(cmd); r != "" {
		return r
	}
	// Re-check the payload of "bash -c ...", "cmd /c ...", "pwsh -Command ...".
	if depth < 3 {
		for _, m := range reShellC.FindAllStringSubmatch(cmd, -1) {
			inner := m[1] + m[2] + m[3]
			inner = strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(inner)
			if r := checkCommand(inner, home, depth+1); r != "" {
				return r
			}
		}
	}

	if reUserPass.MatchString(cmd) {
		return "Chặn: lệnh chứa chuỗi dạng user/mật_khẩu@tns. Dùng kết nối wallet `/@alias` qua `kg run`." + hint
	}
	if reLongPW.MatchString(cmd) || reSshpass.MatchString(cmd) || dashPassword(cmd) {
		return "Chặn: lệnh có mật khẩu trên dòng lệnh (-p / --password)." + hint
	}
	if reBearer.MatchString(cmd) {
		return "Chặn: lệnh chứa header Authorization: Bearer với token dài." + hint
	}
	if rePwAssign.MatchString(cmd) {
		return "Chặn: lệnh chứa gán PASSWORD=..." + hint
	}
	if reIdentBy.MatchString(cmd) {
		return "Chặn: lệnh chứa IDENTIFIED BY <mật khẩu>." + hint
	}
	return ""
}

// containsPath finds home in n at a path boundary.
func containsPath(n, home string) bool {
	for off := 0; ; {
		i := strings.Index(n[off:], home)
		if i < 0 {
			return false
		}
		end := off + i + len(home)
		if end == len(n) || strings.ContainsRune("/ \t\"'`;|&)<>", rune(n[end])) {
			return true
		}
		off = off + i + 1
	}
}

// checkSegments inspects each simple command (split on ; | & newline ( `).
func checkSegments(cmd string) string {
	powershellRecurse := strings.Contains(strings.ToLower(cmd), "-recurse")
	for _, seg := range reSegSplit.Split(cmd, -1) {
		f := strings.Fields(seg)
		for len(f) > 0 && (f[0] == "sudo" || f[0] == "command" || f[0] == "builtin") {
			f = f[1:]
		}
		if len(f) == 0 {
			continue
		}
		name := strings.ToLower(strings.Trim(f[0], `)"'`))
		if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
			name = name[i+1:]
		}
		name = strings.TrimSuffix(name, ".exe")
		args := f[1:]
		for i, a := range args { // drop redirections and what follows
			if reRedirect.MatchString(a) {
				args = args[:i]
				break
			}
		}
		switch name {
		case "printenv":
			return msgEnv
		case "env":
			if allDash(args) {
				return msgEnv
			}
		case "set":
			if len(args) == 0 {
				return msgEnv
			}
		case "export":
			if len(args) == 0 || (len(args) == 1 && args[0] == "-p") {
				return msgEnv
			}
		case "declare", "typeset":
			if len(args) > 0 && allDash(args) {
				for _, a := range args {
					if strings.ContainsAny(a, "px") {
						return msgEnv
					}
				}
			}
		case "compgen":
			for _, a := range args {
				if a == "-v" || a == "-e" || a == "-ve" || a == "-ev" || a == "variable" || a == "export" {
					return msgEnv
				}
			}
		case "ps":
			for _, a := range args { // BSD "ps e", "ps eww", "ps axe" print each process's environment
				if !strings.HasPrefix(a, "-") && strings.Trim(strings.ToLower(a), "abcdefghijklmnopqrstuvwxyz") == "" && strings.Contains(strings.ToLower(a), "e") {
					return msgEnv
				}
			}
		case "rg", "ag", "ack":
			for _, a := range args {
				if a == "--hidden" || a == "-." || a == "--no-ignore" || a == "--no-ignore-dot" || (len(a) > 2 && strings.Trim(a, "u") == "-") {
					return msgFile
				}
			}
			if reSecretKW.MatchString(strings.Join(args, " ")) {
				return msgGrep
			}
		case "grep", "egrep", "fgrep", "zgrep":
			if reSecretKW.MatchString(strings.Join(args, " ")) && recursiveFlag(args) {
				return msgGrep
			}
		case "findstr":
			if reSecretKW.MatchString(strings.Join(args, " ")) {
				for _, a := range args {
					if strings.HasPrefix(strings.ToLower(a), "/s") {
						return msgGrep
					}
				}
			}
		case "select-string", "sls":
			if powershellRecurse && reSecretKW.MatchString(strings.Join(args, " ")) {
				return msgGrep
			}
		}
	}
	return ""
}

func allDash(args []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return false
		}
	}
	return true
}

func recursiveFlag(args []string) bool {
	for _, a := range args {
		if a == "--recursive" || a == "--dereference-recursive" {
			return true
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsAny(a, "rR") {
			return true
		}
	}
	return false
}

// dashPassword detects "-p<pass>" attached passwords. mysql-style tools are
// strict; for other commands we require a password-looking value so that
// flags like "cp -pr" or "docker run -p8080:80" pass.
func dashPassword(cmd string) bool {
	strict := reMySQLLike.MatchString(cmd)
	for _, m := range reDashP.FindAllStringSubmatch(cmd, -1) {
		v := strings.Trim(m[1], "\"'")
		if v == "" || rePortLike.MatchString(v) {
			continue
		}
		if strict {
			return true
		}
		if len(v) >= 6 && v != strings.ToLower(v) {
			return true
		}
	}
	return false
}
