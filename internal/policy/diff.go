package policy

import (
	"fmt"
	"strings"
	"time"
)

// Change ops.
const (
	ChangeAdd    = "add"
	ChangeMod    = "mod"
	ChangeDel    = "del"
	ChangeOracle = "oracle"
)

// FieldChange is one setting that differs between two versions of a grant.
type FieldChange struct{ Label, Old, New string }

// Change is one difference between the last applied policy and the new one.
type Change struct {
	Op       string // ChangeAdd | ChangeMod | ChangeDel | ChangeOracle
	Secret   string // grant pattern ("" for oracle)
	Prod     bool
	Commands []string // allow_commands of the new grant (of the old one for del)
	Added    []string // mod: allow_commands entries that are new
	Removed  []string // mod: allow_commands entries that are gone
	Delivery string   // new values (old ones for del)
	Approval string
	TTL      string
	Fields   []FieldChange // mod/oracle: settings that changed, besides allow_commands
}

// Warning is one risky setting of the new policy.
type Warning struct{ Secret, Msg string }

// ApprovalText describes an approval mode for a human.
func ApprovalText(a string) string {
	switch a {
	case ApprovalUserPresence:
		return "Hello/điện thoại"
	case ApprovalDevice:
		return "chữ ký điện thoại"
	case ApprovalNone:
		return "KHÔNG hỏi ai"
	case ApprovalDeny:
		return "luôn chặn"
	}
	return a
}

func deliveryText(g Grant) string {
	kind := g.Kind
	if kind == "" {
		kind = "env"
	}
	s := kind
	if g.EnvName != "" {
		s += " " + g.EnvName
	}
	if g.TNSAlias != "" {
		s += ", TNS " + g.TNSAlias
	}
	return s
}

func ttlText(g Grant) string {
	if g.TTL > 0 {
		return durText(g.TTL)
	}
	return "không hết hạn"
}

// durText writes a duration as "8 giờ", "1 giờ 30 phút", "45 giây".
func durText(d time.Duration) string {
	var p []string
	if h := int(d / time.Hour); h > 0 {
		p = append(p, fmt.Sprintf("%d giờ", h))
	}
	if m := int(d % time.Hour / time.Minute); m > 0 {
		p = append(p, fmt.Sprintf("%d phút", m))
	}
	if s := int(d % time.Minute / time.Second); s > 0 || len(p) == 0 {
		p = append(p, fmt.Sprintf("%d giây", s))
	}
	return strings.Join(p, " ")
}

type field struct{ label, value string }

func grantFields(g Grant) []field {
	fs := []field{
		{"cấp dạng", deliveryText(g)},
		{"duyệt", ApprovalText(g.Approval)},
		{"hết hạn", ttlText(g)},
	}
	if g.MaxRuntime > 0 {
		fs = append(fs, field{"chạy tối đa", durText(g.MaxRuntime)})
	}
	if len(g.AllowAs) > 0 {
		fs = append(fs, field{"cho đổi dạng (--as)", strings.Join(g.AllowAs, ", ")})
	}
	return fs
}

func grantKey(g Grant) string { return fmt.Sprint(grantFields(g), g.AllowCommands) }

func newChange(op string, g Grant) Change {
	return Change{Op: op, Secret: g.Pattern, Prod: IsProd(g.Pattern, ""), Commands: g.AllowCommands,
		Delivery: deliveryText(g), Approval: ApprovalText(g.Approval), TTL: ttlText(g)}
}

// Changes lists the differences from old (may be nil: everything is new) to cur.
func Changes(old, cur *Policy) []Change {
	var out []Change
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
		if !had {
			out = append(out, newChange(ChangeAdd, g))
			continue
		}
		if grantKey(o) == grantKey(g) {
			continue
		}
		c := newChange(ChangeMod, g)
		oldCmd, curCmd := map[string]bool{}, map[string]bool{}
		for _, x := range o.AllowCommands {
			oldCmd[x] = true
		}
		for _, x := range g.AllowCommands {
			curCmd[x] = true
			if !oldCmd[x] {
				c.Added = append(c.Added, x)
			}
		}
		for _, x := range o.AllowCommands {
			if !curCmd[x] {
				c.Removed = append(c.Removed, x)
			}
		}
		om := map[string]string{}
		for _, f := range grantFields(o) {
			om[f.label] = f.value
		}
		for _, f := range grantFields(g) {
			ov, was := om[f.label]
			delete(om, f.label)
			if !was {
				ov = "(không đặt)"
			}
			if ov != f.value {
				c.Fields = append(c.Fields, FieldChange{f.label, ov, f.value})
			}
		}
		for _, f := range grantFields(o) { // settings that disappeared (max_runtime, allow_as)
			if _, gone := om[f.label]; gone {
				c.Fields = append(c.Fields, FieldChange{f.label, f.value, "(bỏ)"})
			}
		}
		out = append(out, c)
	}
	if old != nil {
		for _, g := range old.Grants {
			if !curG[g.Pattern] {
				out = append(out, newChange(ChangeDel, g))
			}
		}
	}
	var oo OracleCfg
	if old != nil {
		oo = old.Oracle
	}
	if oo != cur.Oracle {
		c := Change{Op: ChangeOracle}
		for _, f := range []FieldChange{{"java", oo.Java, cur.Oracle.Java}, {"pki_jar", oo.PkiJar, cur.Oracle.PkiJar}, {"tns_admin", oo.TNSAdmin, cur.Oracle.TNSAdmin}} {
			if f.Old != f.New {
				f.Old, f.New = orNone(f.Old), orNone(f.New)
				c.Fields = append(c.Fields, f)
			}
		}
		out = append(out, c)
	}
	return out
}

// Text renders a change as plain text: first line starts with + (thêm), ~ (sửa) or - (bỏ), details
// indented. It is the form the phone shows and the fallback when no table can be drawn.
func (c Change) Text() string {
	var b strings.Builder
	switch c.Op {
	case ChangeAdd:
		b.WriteString("+ THÊM quyền dùng secret " + c.Secret + "\n    lệnh được nhận secret:")
		if len(c.Commands) == 0 {
			b.WriteString(" (không lệnh nào)")
		}
		for _, x := range c.Commands {
			b.WriteString("\n      • " + x)
		}
		fmt.Fprintf(&b, "\n    cấp dạng: %s\n    duyệt: %s\n    hết hạn: %s", c.Delivery, c.Approval, c.TTL)
	case ChangeMod:
		b.WriteString("~ SỬA quyền dùng secret " + c.Secret)
		for _, x := range c.Added {
			b.WriteString("\n    thêm lệnh: " + x)
		}
		for _, x := range c.Removed {
			b.WriteString("\n    bỏ lệnh: " + x)
		}
		for _, f := range c.Fields {
			fmt.Fprintf(&b, "\n    %s: %s → %s", f.Label, f.Old, f.New)
		}
	case ChangeDel:
		b.WriteString("- BỎ quyền dùng secret " + c.Secret + " (lệnh sẽ phải xin duyệt lại hoặc bị chặn)")
	case ChangeOracle:
		b.WriteString("~ SỬA công cụ Oracle (chương trình được cầm mật khẩu DB)")
		for _, f := range c.Fields {
			fmt.Fprintf(&b, "\n    %s: %s → %s", f.Label, f.Old, f.New)
		}
	}
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "(trống)"
	}
	return s
}

// Warnings flags risky settings in cur: approval none, wildcard grants/commands, PROD keys. A PROD
// grant identical to the one in old (the last applied policy, may be nil) was approved before: it is
// returned in keptProd instead of warns so the new risks stand out.
func Warnings(old, cur *Policy) (warns []Warning, keptProd []string) {
	oldKey := map[string]string{}
	if old != nil {
		for _, g := range old.Grants {
			oldKey[g.Pattern] = grantKey(g)
		}
	}
	for _, g := range cur.Grants {
		if g.Approval == ApprovalNone {
			warns = append(warns, Warning{g.Pattern, "approval none: lệnh trong danh sách nhận secret mà không hỏi ai"})
		}
		if strings.ContainsAny(g.Pattern, "*?") {
			warns = append(warns, Warning{g.Pattern, "tên có ký tự đại diện (glob): áp cho mọi secret khớp"})
		}
		if IsProd(g.Pattern, "") {
			if k, ok := oldKey[g.Pattern]; ok && k == grantKey(g) {
				keptProd = append(keptProd, g.Pattern)
			} else {
				warns = append(warns, Warning{g.Pattern, "secret PROD, grant mới/sửa trong lần này"})
			}
		}
		for _, c := range g.AllowCommands {
			if strings.Contains(c, "**") || strings.Fields(c)[0] == "*" || strings.HasSuffix(c, " *") {
				warns = append(warns, Warning{g.Pattern, fmt.Sprintf("lệnh %q có wildcard rộng", c)})
			}
		}
		for _, e := range g.Entries {
			if e.UnpinnedScript() {
				warns = append(warns, Warning{g.Pattern, fmt.Sprintf("allow_commands %q: script không ghim nội dung (sha256): ai sửa được file thì chạy mã tùy ý với secret (kg policy pin <policy.yaml>)", e.Raw)})
			}
		}
	}
	return warns, keptProd
}

// Text renders a warning as one line.
func (w Warning) Text() string { return "CẢNH BÁO " + w.Secret + ": " + w.Msg }
