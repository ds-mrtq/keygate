package policy

import (
	"fmt"
	"slices"
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

// SecretRef identifies a live secret in the vault (used to detect effective-grant changes).
type SecretRef struct {
	Name string
	Env  string
}

// Change is one difference between the last applied policy and the new one.
type Change struct {
	Op       string // ChangeAdd | ChangeMod | ChangeDel | ChangeOracle
	Secret   string // grant pattern, affected secret name, or "" for oracle
	Prod     bool
	Fallback string   // del: wildcard grant pattern that still governs Secret ("" if denied)
	Commands []string // allow_commands of the new grant (of the old one for del, or fallback when Fallback != "")
	Added    []string // mod: allow_commands entries that are new
	Removed  []string // mod: allow_commands entries that are gone
	Delivery string   // new values (old ones for del, or fallback when Fallback != "")
	Approval string
	TTL      string
	Fields   []FieldChange // mod/oracle: settings that changed, besides allow_commands; add/del-with-fallback: optional settings (New only)
}

// Warning is one risky setting of the new policy. Old = its grant is identical to the one in the
// last applied policy: the risk was approved before and is not part of the change under review.
type Warning struct {
	Secret, Msg string
	Old         bool
}

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
		kind = "theo kind của secret" // the broker falls back to the item's kind, not to env
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

// sameGrant compares the parsed settings themselves: rendered text loses list boundaries
// (["a b"] and ["a", "b"] print alike), kind "" vs env, sub-second durations, and any field a
// renderer forgets, each of which would let a change skip review.
func sameGrant(a, b Grant) bool {
	return a.Kind == b.Kind && a.EnvName == b.EnvName && a.TNSAlias == b.TNSAlias && a.Approval == b.Approval &&
		a.TTL == b.TTL && a.MaxRuntime == b.MaxRuntime && slices.Equal(a.AllowAs, b.AllowAs) &&
		slices.Equal(a.AllowCommands, b.AllowCommands)
}

// rawSettings shows every setting unrendered, for a change the readable fields cannot express.
func rawSettings(g Grant) string {
	return fmt.Sprintf("kind=%q env_name=%q tns_alias=%q approval=%q ttl=%s max_runtime=%s allow_as=%q",
		g.Kind, g.EnvName, g.TNSAlias, g.Approval, g.TTL, g.MaxRuntime, g.AllowAs)
}

func newChange(op string, g Grant) Change {
	c := Change{Op: op, Secret: g.Pattern, Prod: IsProd(g.Pattern, ""), Commands: g.AllowCommands,
		Delivery: deliveryText(g), Approval: ApprovalText(g.Approval), TTL: ttlText(g)}
	if op == ChangeAdd {
		for _, f := range grantFields(g)[3:] { // max_runtime, allow_as: the three above have their own fields
			c.Fields = append(c.Fields, FieldChange{Label: f.label, New: f.value})
		}
	}
	return c
}

// globsOverlap reports whether some string matches both glob patterns ('*' = any run, '?' = any single rune).
func globsOverlap(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	na, nb := len(ra), len(rb)
	next := make([]bool, nb+1)
	cur := make([]bool, nb+1)
	next[nb] = true
	for j := nb - 1; j >= 0; j-- {
		next[j] = rb[j] == '*' && next[j+1]
	}
	for i := na - 1; i >= 0; i-- {
		cur[nb] = ra[i] == '*' && next[nb]
		for j := nb - 1; j >= 0; j-- {
			switch {
			case ra[i] == '*':
				cur[j] = next[j] || cur[j+1]
			case rb[j] == '*':
				cur[j] = cur[j+1] || next[j]
			case ra[i] == '?' || rb[j] == '?' || ra[i] == rb[j]:
				cur[j] = next[j+1]
			default:
				cur[j] = false
			}
		}
		next, cur = cur, next
	}
	return next[0]
}

func diffGrantFields(c *Change, o, g Grant) {
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
	if len(c.Added) == 0 && len(c.Removed) == 0 && !slices.Equal(o.AllowCommands, g.AllowCommands) {
		c.Fields = append(c.Fields, FieldChange{"allow_commands", "thứ tự/số lần cũ", "đổi thứ tự hoặc lặp lại mục"})
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
	if len(c.Added) == 0 && len(c.Removed) == 0 && len(c.Fields) == 0 {
		c.Fields = append(c.Fields, FieldChange{"thiết lập", rawSettings(o), rawSettings(g)})
	}
}

// Changes lists the differences from old (may be nil: everything is new) to cur.
// When live vault secrets are provided, it also reports secrets whose governing wildcard grant
// changed due to precedence reordering or wildcard removal.
func Changes(old, cur *Policy, secrets ...SecretRef) []Change {
	var out []Change
	oldG := map[string]Grant{}
	oldPos := map[string]int{}
	if old != nil {
		for i, g := range old.Grants {
			oldG[g.Pattern] = g
			oldPos[g.Pattern] = i
		}
	}
	curG := map[string]Grant{}
	for _, g := range cur.Grants {
		curG[g.Pattern] = g
	}
	secretEnv := map[string]string{}
	for _, sec := range secrets {
		if sec.Name == "" {
			continue
		}
		if _, ok := secretEnv[sec.Name]; !ok || IsProd(sec.Name, sec.Env) {
			secretEnv[sec.Name] = sec.Env
		}
	}
	for i, g := range cur.Grants {
		o, had := oldG[g.Pattern]
		if !had {
			out = append(out, newChange(ChangeAdd, g))
			continue
		}
		var precedes []string
		if isGlob(g.Pattern) {
			gScore := globScore(g.Pattern)
			gOldPos := oldPos[g.Pattern]
			for _, other := range cur.Grants[i+1:] {
				if !isGlob(other.Pattern) {
					continue
				}
				otherOldPos, ok := oldPos[other.Pattern]
				if !ok || otherOldPos >= gOldPos {
					continue
				}
				if globScore(other.Pattern) == gScore && globsOverlap(g.Pattern, other.Pattern) && !sameGrant(g, other) {
					precedes = append(precedes, other.Pattern)
				}
			}
		}
		if sameGrant(o, g) && len(precedes) == 0 {
			continue
		}
		c := newChange(ChangeMod, g)
		if !sameGrant(o, g) {
			diffGrantFields(&c, o, g)
		}
		if len(precedes) > 0 {
			joined := strings.Join(precedes, ", ")
			c.Fields = append(c.Fields, FieldChange{Label: "ưu tiên wildcard", Old: "sau " + joined, New: "trước " + joined})
		}
		out = append(out, c)
	}
	if old != nil {
		for _, g := range old.Grants {
			if _, still := curG[g.Pattern]; !still {
				c := newChange(ChangeDel, g)
				if !isGlob(g.Pattern) {
					if fb, err := cur.Lookup(g.Pattern, secretEnv[g.Pattern]); err == nil {
						c.Fallback = fb.Pattern
						c.Commands = fb.AllowCommands
						c.Delivery = deliveryText(*fb)
						c.Approval = ApprovalText(fb.Approval)
						c.TTL = ttlText(*fb)
						for _, f := range grantFields(*fb)[3:] {
							c.Fields = append(c.Fields, FieldChange{Label: f.label, New: f.value})
						}
					}
				}
				out = append(out, c)
			}
		}
		if len(secrets) > 0 {
			seenSec := map[SecretRef]bool{}
			for _, sec := range secrets {
				if sec.Name == "" || seenSec[sec] {
					continue
				}
				seenSec[sec] = true
				oldRes, oldErr := old.Lookup(sec.Name, sec.Env)
				curRes, curErr := cur.Lookup(sec.Name, sec.Env)
				var oldPat, curPat string
				if oldErr == nil {
					oldPat = oldRes.Pattern
				}
				if curErr == nil {
					curPat = curRes.Pattern
				}
				if oldPat == curPat || curPat == sec.Name || oldPat == sec.Name {
					continue
				}
				_, hadExact := oldG[sec.Name]
				_, hasExact := curG[sec.Name]
				if hadExact && !hasExact {
					continue // exact-grant deletion row already reports fallback
				}
				switch {
				case oldErr == nil && curErr == nil:
					if sameGrant(*oldRes, *curRes) {
						continue
					}
					if _, existed := oldG[curPat]; !existed {
						continue // newly added wildcard already has a ChangeAdd row
					}
					c := newChange(ChangeMod, *curRes)
					c.Secret = sec.Name
					c.Prod = IsProd(sec.Name, sec.Env)
					c.Fields = append(c.Fields, FieldChange{Label: "quyền áp dụng", Old: oldPat, New: curPat})
					diffGrantFields(&c, *oldRes, *curRes)
					out = append(out, c)
				case oldErr != nil && curErr == nil:
					if og, existed := oldG[curPat]; existed && og.Approval != ApprovalDeny {
						c := newChange(ChangeMod, *curRes)
						c.Secret = sec.Name
						c.Prod = IsProd(sec.Name, sec.Env)
						c.Added = append(c.Added, curRes.AllowCommands...)
						c.Fields = append(c.Fields,
							FieldChange{Label: "quyền áp dụng", Old: "(bị chặn)", New: curPat},
							FieldChange{Label: "duyệt", Old: ApprovalText(ApprovalDeny), New: ApprovalText(curRes.Approval)},
						)
						out = append(out, c)
					}
				case oldErr == nil && curErr != nil:
					if cg, still := curG[oldPat]; still && cg.Approval != ApprovalDeny {
						c := Change{
							Op:       ChangeMod,
							Secret:   sec.Name,
							Prod:     IsProd(sec.Name, sec.Env),
							Approval: ApprovalText(ApprovalDeny),
							TTL:      ttlText(Grant{}),
							Removed:  oldRes.AllowCommands,
							Fields: []FieldChange{
								{Label: "quyền áp dụng", Old: oldPat, New: "(bị chặn)"},
								{Label: "duyệt", Old: ApprovalText(oldRes.Approval), New: ApprovalText(ApprovalDeny)},
							},
						}
						out = append(out, c)
					}
				}
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
		for _, f := range c.Fields {
			fmt.Fprintf(&b, "\n    %s: %s", f.Label, f.New)
		}
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
		if c.Fallback != "" {
			b.WriteString("- BỎ quyền dùng secret " + c.Secret + " (rơi về grant wildcard " + c.Fallback + ")\n    lệnh được nhận secret (từ " + c.Fallback + "):")
			if len(c.Commands) == 0 {
				b.WriteString(" (không lệnh nào)")
			}
			for _, x := range c.Commands {
				b.WriteString("\n      • " + x)
			}
			fmt.Fprintf(&b, "\n    cấp dạng: %s\n    duyệt: %s\n    hết hạn: %s", c.Delivery, c.Approval, c.TTL)
			for _, f := range c.Fields {
				fmt.Fprintf(&b, "\n    %s: %s", f.Label, f.New)
			}
		} else {
			b.WriteString("- BỎ quyền dùng secret " + c.Secret + " (lệnh sẽ phải xin duyệt lại hoặc bị chặn)")
		}
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

// Warnings flags risky settings in cur: approval none, wildcard grants/commands, PROD keys. A grant
// identical to the one in old (the last applied policy, may be nil) was approved before: its
// warnings carry Old, and a PROD one is returned in keptProd instead of a PROD warning, so the
// risks of this change stand out.
func Warnings(old, cur *Policy) (warns []Warning, keptProd []string) {
	oldG := map[string]Grant{}
	if old != nil {
		for _, g := range old.Grants {
			oldG[g.Pattern] = g
		}
	}
	for _, g := range cur.Grants {
		o, had := oldG[g.Pattern]
		same := had && sameGrant(o, g)
		add := func(msg string) { warns = append(warns, Warning{Secret: g.Pattern, Msg: msg, Old: same}) }
		if g.Approval == ApprovalNone {
			add("approval none: lệnh trong danh sách nhận secret mà không hỏi ai")
		}
		if strings.ContainsAny(g.Pattern, "*?") {
			add("tên có ký tự đại diện (glob): áp cho mọi secret khớp")
		}
		if IsProd(g.Pattern, "") {
			if same {
				keptProd = append(keptProd, g.Pattern)
			} else {
				add("secret PROD, grant mới/sửa trong lần này")
			}
		}
		for _, c := range g.AllowCommands {
			if strings.Contains(c, "**") || strings.Fields(c)[0] == "*" || strings.HasSuffix(c, " *") {
				add(fmt.Sprintf("lệnh %q có wildcard rộng", c))
			}
		}
		for _, e := range g.Entries {
			if e.UnpinnedScript() {
				add(fmt.Sprintf("allow_commands %q: script không ghim nội dung (sha256): ai sửa được file thì chạy mã tùy ý với secret (kg policy pin <policy.yaml>)", e.Raw))
			}
		}
	}
	return warns, keptProd
}

// Text renders a warning as one line.
func (w Warning) Text() string { return "CẢNH BÁO " + w.Secret + ": " + w.Msg }
