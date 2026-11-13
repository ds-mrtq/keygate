package policy

import (
	"bytes"
	"fmt"
	"strings"

	"keygate/internal/allowlist"
)

// PinChange is one allow_commands item rewritten by PinText.
type PinChange struct {
	Old, New string
}

// PinText adds (or refreshes) `sha256:<hex>` after each non-glob path: token of the interpreter /
// pinnable-shell entries of a policy file. Only the text of those entries changes; every other
// byte of data is kept. Items whose file cannot be hashed, or whose text cannot be located
// unambiguously in the file, are reported in errs and left alone. The policy is NOT applied.
func PinText(data []byte, hash func(path string) (string, error)) (out []byte, changes []PinChange, errs []error) {
	p, err := Parse(data)
	if err != nil {
		return nil, nil, []error{err}
	}
	out = data
	seen := map[string]bool{}
	for _, g := range p.Grants {
		for _, raw := range g.AllowCommands {
			if seen[raw] {
				continue
			}
			seen[raw] = true
			nw, err := allowlist.PinRaw(raw, hash)
			if err != nil {
				errs = append(errs, fmt.Errorf("%q: %w", raw, err))
				continue
			}
			if nw == raw {
				continue
			}
			res, n := replaceScalar(out, raw, nw)
			if n == 0 {
				errs = append(errs, fmt.Errorf("%q: không tìm thấy nguyên văn trong file (viết bằng escape YAML?), sửa tay", raw))
				continue
			}
			out = res
			changes = append(changes, PinChange{Old: raw, New: nw})
		}
	}
	return out, changes, errs
}

// replaceScalar replaces every occurrence of old that is a whole YAML scalar (quoted, or a block /
// flow list item) and not a fragment of a longer item. Returns the new text and the count.
func replaceScalar(data []byte, old, nw string) ([]byte, int) {
	var b bytes.Buffer
	n, pos := 0, 0
	ob := []byte(old)
	for {
		i := bytes.Index(data[pos:], ob)
		if i < 0 {
			break
		}
		i += pos
		end := i + len(ob)
		if scalarBounds(data, i, end) {
			b.Write(data[pos:i])
			b.WriteString(nw)
			n++
		} else {
			b.Write(data[pos:end])
		}
		pos = end
	}
	if n == 0 {
		return data, 0
	}
	b.Write(data[pos:])
	return b.Bytes(), n
}

func scalarBounds(data []byte, start, end int) bool {
	if end < len(data) {
		switch data[end] {
		case '"', '\'', ',', ']', '\r', '\n', '#':
		case ' ', '\t':
			rest := strings.TrimLeft(string(data[end:min(len(data), end+200)]), " \t")
			if !(strings.HasPrefix(rest, "#") || strings.HasPrefix(rest, "\n") || strings.HasPrefix(rest, "\r") || strings.HasPrefix(rest, ",") || strings.HasPrefix(rest, "]")) {
				return false
			}
		default:
			return false
		}
	}
	if start == 0 {
		return false
	}
	switch data[start-1] {
	case '"', '\'', '[', ',':
		return true
	}
	j := start - 1
	for j >= 0 && (data[j] == ' ' || data[j] == '\t') {
		j--
	}
	return j >= 0 && (data[j] == '-' || data[j] == '[' || data[j] == ',')
}
