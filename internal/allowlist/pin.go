package allowlist

import (
	"fmt"
	"strings"
)

// UnpinnedScript reports an interpreter or pinnable-shell entry whose first argument is a path:
// pattern without a `sha256:` pin: whoever can edit that file runs arbitrary code with the secret.
func (e Entry) UnpinnedScript() bool {
	base := BaseName(e.Cmd)
	if !isInterpreter(base) && !isPinnable(base) {
		return false
	}
	if len(e.Args) == 0 || !strings.HasPrefix(strings.TrimPrefix(e.Args[0], "@"), "path:") {
		return false
	}
	_, pinned := e.Pins[0]
	return !pinned
}

// tokenSpans returns the [start,end) byte range of every token of s, using the same rules as
// tokenize (space separated, double quotes group).
func tokenSpans(s string) [][2]int {
	var out [][2]int
	inQ, has, start := false, false, 0
	for i, r := range s {
		switch {
		case r == '"':
			if !has {
				start = i
			}
			inQ = !inQ
			has = true
		case r == ' ' && !inQ:
			if has {
				out = append(out, [2]int{start, i})
				has = false
			}
		default:
			if !has {
				start = i
			}
			has = true
		}
	}
	if has {
		out = append(out, [2]int{start, len(s)})
	}
	return out
}

// PinRaw returns raw (one allow_commands item) with `sha256:<hex>` placed right after every
// non-glob path: token of an interpreter/pinnable-shell entry (an existing pin is replaced), the
// rest of the string untouched. hash maps a file path to "sha256:<hex>" (FileHash).
func PinRaw(raw string, hash func(path string) (string, error)) (string, error) {
	toks, err := tokenize(raw)
	if err != nil {
		return raw, err
	}
	spans := tokenSpans(raw)
	if len(toks) == 0 || len(toks) != len(spans) {
		return raw, fmt.Errorf("không tách được mục %q", raw)
	}
	base := BaseName(toks[0])
	if !isInterpreter(base) && !isPinnable(base) {
		return raw, nil
	}
	out := raw
	for k := len(toks) - 1; k >= 1; k-- {
		p := strings.TrimPrefix(toks[k], "@")
		if !strings.HasPrefix(p, "path:") {
			continue
		}
		path := strings.TrimPrefix(p, "path:")
		if strings.ContainsAny(path, "*?[") {
			continue
		}
		h, err := hash(path)
		if err != nil {
			return raw, fmt.Errorf("%s: %w", path, err)
		}
		if k+1 < len(toks) && strings.HasPrefix(toks[k+1], "sha256:") {
			if toks[k+1] != h {
				out = out[:spans[k+1][0]] + h + out[spans[k+1][1]:]
			}
			continue
		}
		out = out[:spans[k][1]] + " " + h + out[spans[k][1]:]
	}
	return out, nil
}
