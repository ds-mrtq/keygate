package approve

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxPrompt caps any text shown to a human for approval.
const MaxPrompt = 300

var (
	ansiCSI = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]")
	ansiOSC = regexp.MustCompile("\x1b\\][^\x07\x1b]*(\x07|\x1b\\\\)?")
)

// Sanitize strips ANSI escapes and every control/format character (C0, C1, bidi overrides) and
// caps the result at max runes, so agent-controlled text cannot rewrite what the human reads.
func Sanitize(s string, max int) string {
	s = ansiOSC.ReplaceAllString(s, "")
	s = ansiCSI.ReplaceAllString(s, "")
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if max > 0 {
		if rs := []rune(out); len(rs) > max {
			out = string(rs[:max]) + "…"
		}
	}
	return out
}

// FormatArgv renders argv as a quoted array, e.g. ["sql" "/@X"], sanitized and capped.
func FormatArgv(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = strconv.Quote(Sanitize(a, MaxPrompt))
	}
	return Sanitize("["+strings.Join(parts, " ")+"]", MaxPrompt)
}
