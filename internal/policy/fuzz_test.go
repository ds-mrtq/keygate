package policy

import (
	"errors"
	"strings"
	"testing"
)

func fakeHash(path string) (string, error) {
	return "sha256:" + strings.Repeat("ab", 32), nil
}

// FuzzParse feeds arbitrary policy.yaml text to Parse. It must never panic, and an accepted policy
// must satisfy the rules Parse promises to enforce (fail closed on anything else).
func FuzzParse(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte("grants:\n  a/b:\n    approval: deny\n"))
	f.Add([]byte("\ufeffgrants:\r\n  'it''s':\r\n    tns_alias: \"x # y\" # c\r\n"))
	f.Add([]byte("grants:\n  x:\n    allow_commands: [\"/opt/t sha256:" + strings.Repeat("0", 64) + "\"]\n    approval: none\n"))
	f.Add([]byte("oracle:\n  java: /j\ngrants:\n  \"k\": \n    allow_as: [env, file, wallet]\n    ttl: 3d\n"))
	f.Add([]byte("grants:\n\t x:\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, g := range p.Grants {
			if seen[g.Pattern] {
				t.Fatalf("duplicate grant %q accepted", g.Pattern)
			}
			seen[g.Pattern] = true
			if !kinds[g.Kind] {
				t.Fatalf("grant %q: kind %q accepted", g.Pattern, g.Kind)
			}
			switch g.Approval {
			case ApprovalUserPresence, ApprovalDevice, ApprovalNone, ApprovalDeny:
			default:
				t.Fatalf("grant %q: approval %q accepted", g.Pattern, g.Approval)
			}
			if len(g.Entries) != len(g.AllowCommands) {
				t.Fatalf("grant %q: %d entries for %d allow_commands", g.Pattern, len(g.Entries), len(g.AllowCommands))
			}
			for _, e := range g.Entries {
				if g.Approval == ApprovalNone && !e.HasContentPin() {
					t.Fatalf("grant %q: approval none with unpinned %q", g.Pattern, e.Raw)
				}
			}
			for _, a := range g.AllowAs {
				if !asKinds[a] {
					t.Fatalf("grant %q: allow_as %q accepted", g.Pattern, a)
				}
			}
			got, err := p.Lookup(g.Pattern, "")
			switch {
			case g.Approval == ApprovalDeny || (IsProd(g.Pattern, "") && g.Approval != ApprovalUserPresence):
				if !errors.Is(err, ErrDenied) {
					t.Fatalf("Lookup(%q) = %v, %v; want denied", g.Pattern, got, err)
				}
			case err != nil || got.Pattern != g.Pattern:
				t.Fatalf("Lookup(%q) = %v, %v; exact key must win", g.Pattern, got, err)
			}
		}
		out, _, errs := PinText(data, fakeHash)
		if errs != nil {
			return
		}
		p2, err := Parse(out)
		if err != nil {
			t.Fatalf("PinText output no longer parses: %v\n%s", err, out)
		}
		if len(p2.Grants) != len(p.Grants) {
			t.Fatalf("PinText changed grant count %d -> %d", len(p.Grants), len(p2.Grants))
		}
	})
}

func dquote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func squote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// FuzzQuotedScalarRoundTrip: any one-line string written as a double- or single-quoted YAML
// scalar (key, field value and list item, with a trailing comment) parses back unchanged.
func FuzzQuotedScalarRoundTrip(f *testing.F) {
	f.Add("C:\\me\\tmp", "it's # not a comment")
	f.Add(`a\"b\`, "''")
	f.Add("", " lead and trail ")
	f.Add("\ufeff#", "\t:x, ]")
	f.Fuzz(func(t *testing.T, a, b string) {
		if strings.ContainsAny(a+b, "\r\n") {
			return
		}
		for _, q := range []func(string) string{dquote, squote} {
			doc := "grants:\n  " + q(a) + ": # k\n    tns_alias: " + q(b) + " # v\n"
			raw, err := parseDoc([]byte(doc))
			if err != nil {
				t.Fatalf("parseDoc(%q): %v", doc, err)
			}
			if len(raw.grants) != 1 || raw.grants[0].name != a || raw.grants[0].fields["tns_alias"] != b {
				t.Fatalf("parseDoc(%q) = %+v", doc, raw.grants[0])
			}
			list := "[" + q(a) + ", " + q(b) + "]"
			l, err := parseList(stripComment(list + " # c"))
			if err != nil || len(l) != 2 || l[0] != a || l[1] != b {
				t.Fatalf("parseList(%q) = %q, %v", list, l, err)
			}
		}
	})
}
