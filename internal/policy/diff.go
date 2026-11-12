package policy

import (
	"fmt"
	"strings"
)

func grantLine(g Grant) string {
	ttl := "không hết hạn"
	if g.TTL > 0 {
		ttl = g.TTL.String()
	}
	return fmt.Sprintf("kind=%q env_name=%q tns_alias=%q approval=%s ttl=%s max_runtime=%s allow_as=%v allow_commands=%q",
		g.Kind, g.EnvName, g.TNSAlias, g.Approval, ttl, g.MaxRuntime, g.AllowAs, g.AllowCommands)
}

// Diff lists human-readable changes from old (may be nil) to cur, one per line.
func Diff(old, cur *Policy) []string {
	var out []string
	oldG := map[string]Grant{}
	if old != nil {
		for _, g := range old.Grants {
			oldG[g.Pattern] = g
		}
	}
	curG := map[string]bool{}
	for _, g := range cur.Grants {
		curG[g.Pattern] = true
		o, had := oldG[g.Pattern]
		switch {
		case !had:
			out = append(out, "+ grant "+g.Pattern+": "+grantLine(g))
		case grantLine(o) != grantLine(g):
			out = append(out, "~ grant "+g.Pattern+":\n    trước: "+grantLine(o)+"\n    sau:   "+grantLine(g))
		}
	}
	if old != nil {
		for _, g := range old.Grants {
			if !curG[g.Pattern] {
				out = append(out, "- grant "+g.Pattern)
			}
		}
	}
	var oo OracleCfg
	if old != nil {
		oo = old.Oracle
	}
	if oo != cur.Oracle {
		out = append(out, fmt.Sprintf("~ oracle: java=%q pki_jar=%q tns_admin=%q (trước: java=%q pki_jar=%q tns_admin=%q)",
			cur.Oracle.Java, cur.Oracle.PkiJar, cur.Oracle.TNSAdmin, oo.Java, oo.PkiJar, oo.TNSAdmin))
	}
	return out
}

// Warnings flags risky settings in cur: approval none, wildcard grants/commands, PROD keys.
func Warnings(cur *Policy) []string {
	var out []string
	for _, g := range cur.Grants {
		if g.Approval == ApprovalNone {
			out = append(out, fmt.Sprintf("CẢNH BÁO %s: approval: none (chạy không cần duyệt)", g.Pattern))
		}
		if strings.ContainsAny(g.Pattern, "*?") {
			out = append(out, fmt.Sprintf("CẢNH BÁO %s: khóa là glob (áp cho mọi secret khớp)", g.Pattern))
		}
		if IsProd(g.Pattern, "") {
			out = append(out, fmt.Sprintf("CẢNH BÁO %s: khóa PROD", g.Pattern))
		}
		for _, c := range g.AllowCommands {
			if strings.Contains(c, "**") || strings.Fields(c)[0] == "*" || strings.HasSuffix(c, " *") {
				out = append(out, fmt.Sprintf("CẢNH BÁO %s: allow_commands %q có wildcard rộng", g.Pattern, c))
			}
		}
	}
	return out
}
