package policy

import (
	"fmt"
	"strings"
)

// stripComment removes a trailing "# ..." that is outside quotes.
func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// parseScalar parses a quoted or bare scalar and returns the rest of the input after it.
func parseScalar(s string, inList bool) (val string, rest string, err error) {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return "", "", nil
	}
	switch s[0] {
	case '"':
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
				if i >= len(s) {
					return "", "", fmt.Errorf("chuỗi chưa đóng")
				}
				switch s[i] {
				case '"', '\\':
					b.WriteByte(s[i])
				default:
					// every other backslash is literal, so Windows paths like "C:\me\tmp" survive
					b.WriteByte('\\')
					b.WriteByte(s[i])
				}
			case '"':
				return b.String(), s[i+1:], nil
			default:
				b.WriteByte(s[i])
			}
		}
		return "", "", fmt.Errorf("chuỗi chưa đóng")
	case '\'':
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			if s[i] == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				return b.String(), s[i+1:], nil
			}
			b.WriteByte(s[i])
		}
		return "", "", fmt.Errorf("chuỗi chưa đóng")
	}
	end := len(s)
	if inList {
		if i := strings.IndexAny(s, ",]"); i >= 0 {
			end = i
		}
	}
	return strings.TrimSpace(s[:end]), s[end:], nil
}

// parseList parses "[a, "b c"]".
func parseList(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return nil, fmt.Errorf("mong đợi danh sách [...]")
	}
	s = s[1:]
	out := []string{}
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return nil, fmt.Errorf("danh sách chưa đóng ']'")
		}
		if s[0] == ']' {
			if strings.TrimSpace(s[1:]) != "" {
				return nil, fmt.Errorf("thừa nội dung sau ']'")
			}
			return out, nil
		}
		v, rest, err := parseScalar(s, true)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		rest = strings.TrimLeft(rest, " \t")
		switch {
		case strings.HasPrefix(rest, ","):
			s = rest[1:]
		case strings.HasPrefix(rest, "]"):
			s = rest
		default:
			return nil, fmt.Errorf("danh sách: mong đợi ',' hoặc ']'")
		}
	}
}

// splitKey splits "key: value" where key may be quoted.
func splitKey(s string) (key, value string, err error) {
	if s != "" && (s[0] == '"' || s[0] == '\'') {
		k, rest, err := parseScalar(s, false)
		if err != nil {
			return "", "", err
		}
		rest = strings.TrimLeft(rest, " \t")
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("thiếu ':' sau khóa")
		}
		return k, strings.TrimSpace(rest[1:]), nil
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && (i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t') {
			return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), nil
		}
	}
	return "", "", fmt.Errorf("thiếu ':'")
}

type rawGrant struct {
	name   string
	fields map[string]string
	lists  map[string][]string
}

type rawDoc struct {
	grants []*rawGrant
	oracle map[string]string
}

// parseDoc parses the policy subset (top-level `grants:` and `oracle:`; order preserved).
func parseDoc(data []byte) (*rawDoc, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimPrefix(text, "\ufeff")
	doc := &rawDoc{oracle: map[string]string{}}
	var cur *rawGrant
	section := ""
	seen := map[string]bool{}
	l1, l2 := -1, -1
	for ln, line := range strings.Split(text, "\n") {
		errf := func(format string, a ...any) error {
			return fmt.Errorf("policy.yaml dòng %d: %s", ln+1, fmt.Sprintf(format, a...))
		}
		if strings.HasPrefix(strings.TrimLeft(line, " "), "\t") {
			return nil, errf("không dùng tab để thụt dòng")
		}
		body := strings.TrimRight(stripComment(line), " \t\r")
		if strings.TrimSpace(body) == "" {
			continue
		}
		indent := len(body) - len(strings.TrimLeft(body, " "))
		content := body[indent:]
		key, val, err := splitKey(content)
		if err != nil {
			return nil, errf("%v", err)
		}
		if indent == 0 {
			if (key != "grants" && key != "oracle") || val != "" || seen[key] {
				return nil, errf("chỉ hỗ trợ khóa gốc 'grants:' và 'oracle:' (mỗi khóa một lần)")
			}
			seen[key] = true
			section, cur, l1, l2 = key, nil, -1, -1
			continue
		}
		switch section {
		case "":
			return nil, errf("nội dung thụt dòng trước khóa gốc")
		case "oracle":
			if l1 < 0 {
				l1 = indent
			}
			if indent != l1 {
				return nil, errf("thụt dòng không hợp lệ trong oracle")
			}
			if _, dup := doc.oracle[key]; dup {
				return nil, errf("trùng trường oracle.%s", key)
			}
			v, rest, err := parseScalar(val, false)
			if err != nil || strings.TrimSpace(rest) != "" {
				return nil, errf("oracle.%s: giá trị không hợp lệ", key)
			}
			doc.oracle[key] = v
			continue
		}
		switch {
		case l1 < 0 || indent == l1:
			l1 = indent
			if val != "" {
				return nil, errf("khóa secret %q phải là map lồng nhau", key)
			}
			for _, g := range doc.grants {
				if g.name == key {
					return nil, errf("trùng khóa grant %q", key)
				}
			}
			cur = &rawGrant{name: key, fields: map[string]string{}, lists: map[string][]string{}}
			doc.grants = append(doc.grants, cur)
			l2 = -1
		case l2 < 0 && indent > l1, indent == l2:
			if cur == nil {
				return nil, errf("trường ngoài grant")
			}
			l2 = indent
			if _, dup := cur.fields[key]; dup {
				return nil, errf("trùng trường %q", key)
			}
			if _, dup := cur.lists[key]; dup {
				return nil, errf("trùng trường %q", key)
			}
			if strings.HasPrefix(val, "[") {
				l, err := parseList(val)
				if err != nil {
					return nil, errf("%s: %v", key, err)
				}
				cur.lists[key] = l
			} else {
				v, rest, err := parseScalar(val, false)
				if err != nil {
					return nil, errf("%s: %v", key, err)
				}
				if strings.TrimSpace(rest) != "" {
					return nil, errf("%s: thừa nội dung sau giá trị", key)
				}
				cur.fields[key] = v
			}
		default:
			return nil, errf("thụt dòng không hợp lệ (chỉ hỗ trợ 2 cấp)")
		}
	}
	return doc, nil
}
