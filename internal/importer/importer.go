// Package importer moves plaintext secrets out of dotenv files and gitleaks
// reports and replaces them with ${secret:NAME} references. Values are never
// logged or included in error messages.
package importer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry is one KEY=VALUE assignment in a dotenv file.
type Entry struct {
	Key   string
	Value string
	Line  int // 1-based line where the assignment starts
}

type parsed struct {
	Entry
	start, end int // byte range of the value token (including quotes)
}

const refMarker = "${secret:"

func isKeyStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isKeyChar(c byte) bool {
	return isKeyStart(c) || (c >= '0' && c <= '9') || c == '.' || c == '-'
}

// scan parses dotenv content into assignments with non-empty values.
func scan(s string) []parsed {
	out, _ := scanA(s)
	return out
}

// scanA is scan plus the 1-based numbers of lines that are neither blank, comment nor KEY=VALUE.
func scanA(s string) ([]parsed, []int) {
	var anomalies []int
	var out []parsed
	for pos := 0; pos < len(s); {
		eol := strings.IndexByte(s[pos:], '\n')
		lineEnd := len(s)
		if eol >= 0 {
			lineEnd = pos + eol
		}
		next := lineEnd + 1
		line := s[pos:lineEnd]
		i := 0
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) || line[i] == '#' || strings.TrimSpace(line[i:]) == "" {
			pos = next
			continue
		}
		if strings.HasPrefix(line[i:], "export") && i+6 < len(line) && (line[i+6] == ' ' || line[i+6] == '\t') {
			i += 6
			for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
				i++
			}
		}
		ks := i
		if i >= len(line) || !isKeyStart(line[i]) {
			anomalies = append(anomalies, startLine(s, pos))
			pos = next
			continue
		}
		for i < len(line) && isKeyChar(line[i]) {
			i++
		}
		key := line[ks:i]
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) || line[i] != '=' {
			anomalies = append(anomalies, startLine(s, pos))
			pos = next
			continue
		}
		i++
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		vs := pos + i // absolute start of value
		var val string
		var ve int
		if vs < len(s) && i < len(line) && (line[i] == '"' || line[i] == '\'') {
			q := line[i]
			j := vs + 1
			var sb strings.Builder
			closed := false
			for j < len(s) {
				c := s[j]
				if q == '"' && c == '\\' && j+1 < len(s) {
					switch s[j+1] {
					case 'n':
						sb.WriteByte('\n')
					case 'r':
						sb.WriteByte('\r')
					case 't':
						sb.WriteByte('\t')
					case '"', '\\', '$':
						sb.WriteByte(s[j+1])
					default:
						sb.WriteByte(c)
						sb.WriteByte(s[j+1])
					}
					j += 2
					continue
				}
				if c == q {
					closed = true
					j++
					break
				}
				sb.WriteByte(c)
				j++
			}
			if !closed { // unterminated quote: treat rest of the line as the value
				val = strings.TrimRight(line[i+1:], "\r")
				ve = lineEnd
				if strings.HasSuffix(line, "\r") {
					ve--
				}
			} else {
				val = sb.String()
				ve = j
			}
		} else {
			raw := line[i:]
			cut := len(raw)
			for k := 0; k < len(raw); k++ {
				if raw[k] == '#' && (k == 0 || raw[k-1] == ' ' || raw[k-1] == '\t') {
					cut = k
					break
				}
			}
			raw = strings.TrimRight(raw[:cut], " \t\r")
			val = raw
			ve = vs + len(raw)
		}
		// advance past the line that holds the end of the value
		if ve > lineEnd {
			e := strings.IndexByte(s[ve:], '\n')
			if e < 0 {
				next = len(s)
			} else {
				next = ve + e + 1
			}
		}
		if val != "" && !strings.Contains(val, refMarker) {
			out = append(out, parsed{Entry: Entry{Key: key, Value: val, Line: startLine(s, pos)}, start: vs, end: ve})
		}
		pos = next
	}
	return out, anomalies
}

// DotenvAnomalies returns the 1-based line numbers of path that are not blank, comments or KEY=VALUE
// (never their content).
func DotenvAnomalies(path string) ([]int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	_, an := scanA(string(b))
	return an, nil
}

func startLine(s string, pos int) int { return strings.Count(s[:pos], "\n") + 1 }

// ParseDotenv returns the assignments in path that hold literal values.
// Empty values and values that already are ${secret:...} references are skipped.
func ParseDotenv(path string) ([]Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ps := scan(string(b))
	out := make([]Entry, len(ps))
	for i, p := range ps {
		out[i] = p.Entry
	}
	return out, nil
}

// RewriteDotenv replaces the value of each key in refs with ${secret:<ref>},
// leaving all other bytes (comments, order, line endings) untouched.
func RewriteDotenv(path string, refs map[string]string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s := string(b)
	ps := scan(s)
	sort.Slice(ps, func(i, j int) bool { return ps[i].start > ps[j].start })
	changed := false
	for _, p := range ps {
		ref, ok := refs[p.Key]
		if !ok {
			continue
		}
		s = s[:p.start] + refMarker + ref + "}" + s[p.end:]
		changed = true
	}
	if !changed {
		return nil
	}
	return atomicWrite(path, []byte(s))
}

// Finding is one entry of an unredacted gitleaks JSON report.
type Finding struct {
	File      string `json:"File"`
	StartLine int    `json:"StartLine"`
	RuleID    string `json:"RuleID"`
	Secret    string `json:"Secret"`
}

// ParseGitleaks reads a gitleaks JSON report. Reports produced with --redact
// are rejected because the original values are not recoverable from them.
func ParseGitleaks(path string) ([]Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fs []Finding
	if err := json.Unmarshal(b, &fs); err != nil {
		return nil, fmt.Errorf("importer: bad gitleaks report: %w", err)
	}
	for i, f := range fs {
		if f.Secret == "" || strings.Contains(f.Secret, "REDACTED") {
			return nil, fmt.Errorf("importer: finding %d (%s) has no unredacted Secret; rerun gitleaks without --redact", i, f.RuleID)
		}
	}
	return fs, nil
}

// RewriteFinding replaces the exact secret string at f.File:f.StartLine with ${secret:<ref>}.
func RewriteFinding(f Finding, ref string) error {
	if f.Secret == "" {
		return errors.New("importer: empty secret in finding")
	}
	b, err := os.ReadFile(f.File)
	if err != nil {
		return err
	}
	s := string(b)
	off, line := 0, 1
	for line < f.StartLine {
		i := strings.IndexByte(s[off:], '\n')
		if i < 0 {
			return fmt.Errorf("importer: %s has fewer than %d lines", f.File, f.StartLine)
		}
		off += i + 1
		line++
	}
	lineEnd := len(s)
	if i := strings.IndexByte(s[off:], '\n'); i >= 0 {
		lineEnd = off + i
	}
	limit := lineEnd
	if strings.Contains(f.Secret, "\n") { // multi-line secrets may extend past the line
		limit = len(s)
	}
	i := strings.Index(s[off:limit], f.Secret)
	if i < 0 {
		return fmt.Errorf("importer: secret not found at %s:%d (file changed since the scan?)", f.File, f.StartLine)
	}
	s = s[:off+i] + refMarker + ref + "}" + s[off+i+len(f.Secret):]
	return atomicWrite(f.File, []byte(s))
}

// SuggestName builds a vault name such as llm/openai-api-key.
func SuggestName(prefix, key string) string {
	n := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix + n
}

// atomicWrite writes data via a temp file in the same directory, then renames,
// preserving the original file mode.
func atomicWrite(path string, data []byte) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kg-import-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}
