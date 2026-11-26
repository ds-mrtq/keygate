// Package redact masks secret values in a byte stream (DESIGN sec 10).
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// MinLen is the shortest value that is redacted.
const MinLen = 4

// Secret is a named value to mask.
type Secret struct {
	Name  string
	Value string
}

type pattern struct {
	b   []byte
	rep []byte
}

// Redactor holds the compiled patterns; safe for concurrent use by several Writers.
type Redactor struct {
	pats   []pattern // longest first
	maxLen int
}

var pctRe = regexp.MustCompile(`%[0-9A-F]{2}`)

// fieldRes match `key: value` / `key=value` lines and `"key": "value"` pairs in a structured
// secret (kubeconfig, YAML, JSON, INI); group 1 is the key, then the value double-quoted,
// single-quoted or bare.
var fieldRes = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?["']?([A-Za-z0-9_.-]+)["']?[ \t]*[:=][ \t]*(?:"((?:[^"\\\r\n]|\\.)*)"|'((?:[^'\r\n]|'')*)'|([^\s"'#,]+))`),
	regexp.MustCompile(`"([A-Za-z0-9_.-]+)"[ \t]*:[ \t]*(?:"((?:[^"\\\r\n]|\\.)*)"|()())`),
}

// credentialKey reports whether a field name in a structured secret holds a credential.
func credentialKey(k string) bool {
	k = strings.ToLower(k)
	for _, w := range []string{"token", "password", "passwd", "secret", "client-key-data", "api-key", "apikey"} {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

// innerValues returns credential field values found inside a structured secret (e.g. the bearer
// token of an imported kubeconfig), so a value parsed out and printed alone is masked too.
func innerValues(v string) []string {
	if !strings.ContainsAny(v, ":=") {
		return nil
	}
	var out []string
	for _, re := range fieldRes {
		for _, m := range re.FindAllStringSubmatch(v, -1) {
			if !credentialKey(m[1]) {
				continue
			}
			vals := []string{m[2] + m[3] + m[4]}
			if strings.Contains(m[2], `\`) {
				var u string
				if json.Unmarshal([]byte(`"`+m[2]+`"`), &u) == nil {
					vals = append(vals, u)
				}
			}
			if strings.Contains(m[3], "''") {
				vals = append(vals, strings.ReplaceAll(m[3], "''", "'"))
			}
			for _, val := range vals {
				if len(val) >= minInterior && val != v {
					out = append(out, val)
				}
			}
		}
	}
	return out
}

// minInterior is the shortest base64 interior fragment that is still matched (avoids noise).
const minInterior = 8

// valueForms returns the literal variants of a value: as given, trimmed, and with CRLF line ends.
func valueForms(v string) []string {
	out := []string{v}
	add := func(s string) {
		if len(s) >= MinLen {
			out = append(out, s)
		}
	}
	t := strings.TrimSpace(v)
	if t != v {
		add(t)
	}
	for _, f := range append([]string(nil), out...) {
		if strings.Contains(f, "\n") && !strings.Contains(f, "\r\n") {
			add(strings.ReplaceAll(f, "\n", "\r\n"))
		}
	}
	return out
}

// b64Interiors returns, for each of the three byte alignments, the base64 text of raw that does not
// depend on neighbouring bytes (leading and trailing characters that mix in unknown bytes are dropped).
func b64Interiors(raw []byte, enc *base64.Encoding) []string {
	var out []string
	for k := 0; k < 3; k++ {
		s := enc.EncodeToString(append(make([]byte, k), raw...))
		lead := [3]int{0, 2, 3}[k]
		trail := 0
		if (len(raw)+k)%3 != 0 {
			trail = 1
		}
		if len(s)-trail-lead >= minInterior {
			out = append(out, s[lead:len(s)-trail])
		}
	}
	return out
}

// New builds a Redactor for the given secrets. Values shorter than MinLen are ignored.
func New(secrets []Secret) *Redactor {
	seen := map[string]bool{}
	r := &Redactor{}
	add := func(s, name string) {
		if len(s) < MinLen || seen[s] {
			return
		}
		seen[s] = true
		r.pats = append(r.pats, pattern{b: []byte(s), rep: []byte("[kg:" + name + "]")})
	}
	for _, s := range secrets {
		if len(s.Value) < MinLen {
			continue
		}
		var vals []string
		for _, v := range append([]string{s.Value}, innerValues(s.Value)...) {
			vals = append(vals, valueForms(v)...)
		}
		for _, f := range vals {
			raw := []byte(f)
			add(f, s.Name)
			add(base64.StdEncoding.EncodeToString(raw), s.Name)
			add(base64.RawStdEncoding.EncodeToString(raw), s.Name)
			add(base64.URLEncoding.EncodeToString(raw), s.Name)
			add(base64.RawURLEncoding.EncodeToString(raw), s.Name)
			for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
				for _, in := range b64Interiors(raw, enc) {
					add(in, s.Name)
				}
			}
			for _, q := range []string{url.QueryEscape(f), url.PathEscape(f)} {
				add(q, s.Name)
				add(pctRe.ReplaceAllStringFunc(q, strings.ToLower), s.Name)
			}
		}
	}
	sort.SliceStable(r.pats, func(i, j int) bool { return len(r.pats[i].b) > len(r.pats[j].b) })
	for _, p := range r.pats {
		if len(p.b) > r.maxLen {
			r.maxLen = len(p.b)
		}
	}
	return r
}

// Bytes redacts a complete buffer.
func (r *Redactor) Bytes(in []byte) []byte {
	out, _ := r.process(nil, in, true)
	return out
}

// String redacts a complete string.
func (r *Redactor) String(s string) string { return string(r.Bytes([]byte(s))) }

// process scans buf; when final is false the last maxLen-1 bytes are left unconsumed.
// Returns the output appended to dst and the unconsumed remainder.
func (r *Redactor) process(dst, buf []byte, final bool) ([]byte, []byte) {
	if len(r.pats) == 0 {
		return append(dst, buf...), nil
	}
	limit := len(buf)
	if !final {
		limit = len(buf) - (r.maxLen - 1)
	}
	i := 0
	for i < limit {
		matched := false
		for _, p := range r.pats {
			if buf[i] == p.b[0] && bytes.HasPrefix(buf[i:], p.b) {
				dst = append(dst, p.rep...)
				i += len(p.b)
				matched = true
				break
			}
		}
		if !matched {
			dst = append(dst, buf[i])
			i++
		}
	}
	if i >= len(buf) {
		return dst, nil
	}
	return dst, buf[i:]
}

// Writer is a streaming redacting io.Writer. Call Flush when the stream ends.
type Writer struct {
	mu   sync.Mutex
	r    *Redactor
	w    io.Writer
	tail []byte
}

// NewWriter wraps w.
func (r *Redactor) NewWriter(w io.Writer) *Writer { return &Writer{r: r, w: w} }

// NewWriter is a shortcut for New(secrets).NewWriter(w).
func NewWriter(w io.Writer, secrets []Secret) *Writer { return New(secrets).NewWriter(w) }

// Write redacts p and forwards what cannot be part of a pattern spanning into later chunks.
func (x *Writer) Write(p []byte) (int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	buf := append(x.tail, p...)
	out, rest := x.r.process(nil, buf, false)
	x.tail = append([]byte(nil), rest...)
	if len(out) > 0 {
		if _, err := x.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush writes out the held-back tail (after redaction). The Writer is reusable afterwards.
func (x *Writer) Flush() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	out, _ := x.r.process(nil, x.tail, true)
	x.tail = nil
	if len(out) == 0 {
		return nil
	}
	_, err := x.w.Write(out)
	return err
}
