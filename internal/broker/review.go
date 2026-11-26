package broker

import (
	"fmt"
	"path"
	"strings"

	"keygate/internal/approve"
	"keygate/internal/policy"
)

// sanitizeLines sanitizes each line of a multi-line text on its own (Sanitize drops newlines).
func sanitizeLines(s string, max int) string {
	ls := strings.Split(s, "\n")
	for i, l := range ls {
		ls[i] = approve.Sanitize(l, max)
	}
	return strings.Join(ls, "\n")
}

// shortCmd shortens an allow_commands entry for a table cell: program and script base names, pins
// marked, other arguments kept: `python path:D:/r/s/fetch.py` -> `python fetch.py`, `"C:/x/sql.exe" sha256:ab…` -> `sql.exe (ghim hash)`.
func shortCmd(c string) string {
	var parts []string
	pinned := false
	for i, f := range splitQuoted(c) {
		switch {
		case strings.HasPrefix(f, "sha256:"):
			pinned = true
		case strings.HasPrefix(f, "path:"):
			parts = append(parts, path.Base(strings.ReplaceAll(strings.TrimPrefix(f, "path:"), `\`, "/")))
		case i == 0: // the program; later arguments (e.g. /@HTTEST) stay as written
			parts = append(parts, path.Base(strings.ReplaceAll(f, `\`, "/")))
		default:
			parts = append(parts, f)
		}
	}
	s := strings.Join(parts, " ")
	if pinned {
		s += " (ghim hash)"
	}
	return s
}

// splitQuoted splits on spaces outside double quotes and drops the quotes.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	in, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			in, has = !in, true
		case r == ' ' && !in:
			if has {
				out = append(out, cur.String())
			}
			cur.Reset()
			has = false
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

func shortCmds(cs []string) string {
	if len(cs) == 0 {
		return "(không lệnh nào)"
	}
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = shortCmd(c)
	}
	return strings.Join(out, "; ")
}

// vaultSecrets returns the live (non-deleted) secrets in s so policy diffs can detect effective-grant changes.
func vaultSecrets(s *session) []policy.SecretRef {
	if s == nil || s.st == nil {
		return nil
	}
	items := s.st.List()
	out := make([]policy.SecretRef, 0, len(items))
	for _, it := range items {
		if it.Deleted || it.Name == "" {
			continue
		}
		out = append(out, policy.SecretRef{Name: it.Name, Env: it.Env})
	}
	return out
}

// policyReview builds what the approver of `kg policy apply` sees: the plain text (phone, fallback)
// and the table of the local dialog. base is the last applied policy (nil = none trusted).
func policyReview(polPath string, base, p *policy.Policy, oldVer uint64, secrets ...policy.SecretRef) (string, *approve.ReviewDoc, int, int) {
	changes := policy.Changes(base, p, secrets...)
	warns, keptProd := policy.Warnings(base, p)
	doc := &approve.ReviewDoc{
		Action: fmt.Sprintf("xin áp dụng policy.yaml thành v%d", oldVer+1),
		Note:   "Policy quyết định chương trình nào được nhận secret nào khi chạy kg run. Áp dụng xong, phiên làm việc và grant tạm bị hủy.",
	}
	var t strings.Builder
	fmt.Fprintf(&t, "Việc cần duyệt: áp dụng %s thành policy v%d.\n", approve.Sanitize(polPath, 500), oldVer+1)
	t.WriteString(doc.Note + " Grant đã duyệt của lệnh không còn trong policy bị xóa.\n\n")
	switch {
	case base == nil:
		t.WriteString("THAY ĐỔI: không có bản đã duyệt đáng tin để so, liệt kê toàn bộ policy\n")
		doc.Badges = append(doc.Badges, approve.Badge{Text: "chưa có bản cũ để so", Tone: approve.ToneWarn})
	case len(changes) == 0:
		t.WriteString("THAY ĐỔI: không có (chỉ đổi định dạng/ghi chú trong file)\n")
		doc.Badges = append(doc.Badges, approve.Badge{Text: "không đổi quyền nào", Tone: approve.ToneMuted})
	default:
		fmt.Fprintf(&t, "THAY ĐỔI so với v%d (%d):\n", oldVer, len(changes))
	}
	count := map[string]int{}
	for _, c := range changes {
		t.WriteString(sanitizeLines(c.Text(), 2000) + "\n\n")
		count[c.Op]++
		doc.Rows = append(doc.Rows, changeRow(c))
	}
	for _, b := range []struct{ op, text, tone string }{
		{policy.ChangeAdd, "thêm", approve.ToneAdd}, {policy.ChangeMod, "sửa", approve.ToneMod},
		{policy.ChangeDel, "bỏ", approve.ToneDel}, {policy.ChangeOracle, "sửa Oracle", approve.ToneMod},
	} {
		if n := count[b.op]; n > 0 {
			doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d %s", n, b.text), Tone: b.tone})
		}
	}
	var news []policy.Warning
	nOld := 0
	for _, w := range warns {
		if w.Old {
			nOld++
		} else {
			news = append(news, w)
		}
	}
	if len(news) > 0 {
		fmt.Fprintf(&t, "CẢNH BÁO của thay đổi này (%d):\n", len(news))
		for _, w := range news {
			t.WriteString(approve.Sanitize(w.Text(), 1000) + "\n")
			doc.Rows = append(doc.Rows, warnRow(w))
		}
		t.WriteString("\n")
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d cảnh báo", len(news)), Tone: approve.ToneWarn})
	} else {
		doc.Badges = append(doc.Badges, approve.Badge{Text: "thay đổi không có cảnh báo", Tone: approve.ToneAdd})
	}
	// Grants identical to the applied version were approved before: counted here, listed in the
	// tray's Policy window, so this dialog only holds what is being decided now.
	if nOld > 0 || len(keptProd) > 0 {
		fmt.Fprintf(&t, "Không đổi so với v%d: %d cảnh báo cũ, %d grant secret PROD giữ nguyên (xem ở cửa sổ Policy của khay KeyGate).\n", oldVer, nOld, len(keptProd))
	}
	if nOld > 0 {
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d cảnh báo cũ (xem ở cửa sổ Policy)", nOld), Tone: approve.ToneMuted})
	}
	if len(keptProd) > 0 {
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d PROD giữ nguyên", len(keptProd)), Tone: approve.ToneMuted})
	}
	doc.Text = t.String()
	return doc.Text, doc, len(changes), len(news)
}

func warnRow(w policy.Warning) approve.ReviewRow {
	return approve.ReviewRow{Group: approve.GroupWarn, Op: "warn", Label: "Cảnh báo",
		Secret: approve.Sanitize(w.Secret, 200), Prod: policy.IsProd(w.Secret, ""),
		What: approve.Sanitize(w.Msg, 500), Detail: approve.Sanitize(w.Text(), 1000)}
}

func changeRow(c policy.Change) approve.ReviewRow {
	r := approve.ReviewRow{Group: approve.GroupChange, Op: c.Op, Secret: approve.Sanitize(c.Secret, 200), Prod: c.Prod,
		Approval: approve.Sanitize(c.Approval, 100), TTL: approve.Sanitize(c.TTL, 50), Detail: sanitizeLines(c.Text(), 2000)}
	switch c.Op {
	case policy.ChangeAdd:
		r.Label, r.What = "Thêm", shortCmds(c.Commands)
		for _, f := range c.Fields { // max_runtime, allow_as: otherwise only in the detail pane
			r.What += "; " + f.Label + ": " + f.New
		}
	case policy.ChangeDel:
		r.Label = "Bỏ"
		if c.Fallback != "" {
			r.What = fmt.Sprintf("rơi về %s: %s", c.Fallback, shortCmds(c.Commands))
			for _, f := range c.Fields {
				r.What += "; " + f.Label + ": " + f.New
			}
		} else {
			r.What = "không lệnh nào được nhận nữa"
		}
	case policy.ChangeOracle:
		r.Label, r.Secret, r.What = "Sửa", "(công cụ Oracle)", "đổi chương trình được cầm mật khẩu DB"
	default:
		r.Label = "Sửa"
		var w []string
		for _, f := range c.Fields { // settings first: a long command list must not truncate them away
			w = append(w, f.Label+": "+f.Old+" → "+f.New)
		}
		for _, x := range c.Added {
			w = append(w, "+ "+shortCmd(x))
		}
		for _, x := range c.Removed {
			w = append(w, "− "+shortCmd(x))
		}
		r.What = strings.Join(w, "; ")
	}
	r.What = approve.Sanitize(r.What, 500)
	return r
}

// peerParts turns a peer string ("pid=N exe=PATH cha=a.exe(1)<b.exe(2)") into the requester
// ("kg.exe (pid N)") and its ancestors ("a.exe ← b.exe").
func peerParts(peer string) (who, chain string) {
	rest, ok := strings.CutPrefix(peer, "pid=")
	if !ok {
		return peer, ""
	}
	pid, rest, _ := strings.Cut(rest, " ")
	rest, cha, _ := strings.Cut(rest, " cha=")
	if strings.HasPrefix(rest, "uid=") { // linux: "uid=N exe=PATH"
		_, rest, _ = strings.Cut(rest, " ")
	}
	exe, ok := strings.CutPrefix(rest, "exe=")
	if !ok || exe == "" {
		return peer, ""
	}
	who = path.Base(strings.ReplaceAll(exe, `\`, "/")) + " (pid " + pid + ")"
	if cha != "" {
		chain = strings.ReplaceAll(cha, "<", " ← ")
	}
	return who, chain
}
