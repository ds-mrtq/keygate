package wingui

import (
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"

	"keygate/internal/approve"
)

// LogTimeLayout is the timestamp the tray writes before every broker.log entry.
const LogTimeLayout = "2006-01-02 15:04:05"

// Log levels: pick the icon and the badge of an entry.
const (
	LevelError  = "error"
	LevelWarn   = "warn"
	LevelOK     = "ok"
	LevelLock   = "lock"
	LevelUnlock = "unlock"
	LevelCancel = "cancel"
	LevelInfo   = "info"
)

// LogEntry is one event of broker.log, readied for the log window.
type LogEntry struct {
	Time   string `json:"time"`   // "12/11 14:20:05", "" for lines written before timestamps
	Source string `json:"source"` // "broker" | "khay"
	Level  string `json:"level"`
	Title  string `json:"title"` // short, human wording
	Detail string `json:"detail"`
	Run    string `json:"run"` // group label: one tray start to the next
}

var (
	reStamp  = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (.*)$`)
	reSrc    = regexp.MustCompile(`^\[(broker|tray)\] ?(.*)$`)
	reSesOn  = regexp.MustCompile(`^phiên làm việc (\S+) đã mở`)
	reSesOff = regexp.MustCompile(`^phiên làm việc (\S+) đã kết thúc`)
	rePolicy = regexp.MustCompile(`^policy (v\d+) áp dụng`)
	reUnlock = regexp.MustCompile(`^đã mở khóa \(thiết bị (\S+)\)`)
	reClixml = regexp.MustCompile(`<S S="Error">(.*?)</S>`)
	reXEsc   = regexp.MustCompile(`_x([0-9A-Fa-f]{4})_`)
)

// ParseLog turns broker.log into entries, oldest first. An entry starts at a line with a timestamp
// or a [broker]/[tray] tag; other lines continue the previous entry.
func ParseLog(text string) []LogEntry {
	type raw struct {
		t   time.Time
		src string
		msg []string
	}
	var rs []raw
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		var ts time.Time
		rest := line
		if m := reStamp.FindStringSubmatch(line); m != nil {
			if t, err := time.ParseInLocation(LogTimeLayout, m[1], time.Local); err == nil {
				ts, rest = t, m[2]
			}
		}
		if m := reSrc.FindStringSubmatch(rest); m != nil {
			rs = append(rs, raw{ts, m[1], []string{m[2]}})
			continue
		}
		if !ts.IsZero() || len(rs) == 0 {
			if strings.TrimSpace(rest) != "" {
				rs = append(rs, raw{ts, "broker", []string{rest}})
			}
			continue
		}
		rs[len(rs)-1].msg = append(rs[len(rs)-1].msg, line)
	}
	var out []LogEntry
	run, runs := "Trước lần khởi động đầu tiên trong file", 0
	for _, r := range rs {
		msg := strings.TrimRight(strings.Join(r.msg, "\n"), "\n ")
		if r.src == "tray" && strings.HasPrefix(msg, "icon khay sẵn sàng") {
			runs++
			if r.t.IsZero() {
				run = fmt.Sprintf("Lần chạy thứ %d trong file (chưa ghi giờ)", runs)
			} else {
				run = "Lần chạy từ " + r.t.Format("02/01/2006 15:04")
			}
		}
		e := describe(msg)
		e.Source = map[string]string{"tray": "khay"}[r.src]
		if e.Source == "" {
			e.Source = r.src
		}
		if !r.t.IsZero() {
			e.Time = r.t.Format("02/01 15:04:05")
		}
		e.Run = run
		out = append(out, e)
	}
	return out
}

// describe gives a message its level and short title; Detail keeps the full text.
func describe(msg string) LogEntry {
	first, _, _ := strings.Cut(msg, "\n")
	e := LogEntry{Level: LevelInfo, Title: first, Detail: msg}
	if strings.Contains(msg, "#< CLIXML") { // PowerShell stderr: keep only its error records
		var errs []string
		for _, m := range reClixml.FindAllStringSubmatch(msg, -1) {
			s := reXEsc.ReplaceAllStringFunc(m[1], func(x string) string {
				var r rune
				for _, c := range x[2:6] {
					r = r*16 + hexVal(c)
				}
				return string(r)
			})
			errs = append(errs, strings.TrimSpace(html.UnescapeString(s)))
		}
		head, _, _ := strings.Cut(first, "#< CLIXML")
		e.Title = strings.TrimRight(head, " :") + " (PowerShell)"
		if len(errs) > 0 {
			e.Detail = strings.TrimSpace(head) + "\n" + strings.Join(errs, "\n")
		} else {
			e.Detail = strings.TrimSpace(head) + "\n(PowerShell không kèm thông báo lỗi; chỉ có bản ghi tiến trình)"
		}
		e.Level = LevelError
		return e
	}
	switch {
	case strings.HasPrefix(msg, "lắng nghe "):
		e.Level, e.Title = LevelOK, "Broker khởi động, chờ lệnh kg"
	case strings.HasPrefix(msg, "icon khay sẵn sàng"):
		e.Level, e.Title = LevelOK, "Khay KeyGate sẵn sàng"
	case reUnlock.MatchString(msg):
		e.Level, e.Title = LevelUnlock, "Mở khóa vault (thiết bị "+reUnlock.FindStringSubmatch(msg)[1]+")"
	case msg == "đã khóa":
		e.Level, e.Title = LevelLock, "Khóa vault"
	case reSesOn.MatchString(msg):
		e.Level, e.Title = LevelUnlock, "Mở phiên làm việc "+reSesOn.FindStringSubmatch(msg)[1]
	case reSesOff.MatchString(msg):
		e.Level, e.Title = LevelLock, "Kết thúc phiên làm việc "+reSesOff.FindStringSubmatch(msg)[1]
	case rePolicy.MatchString(msg):
		e.Level, e.Title = LevelOK, "Áp dụng policy "+rePolicy.FindStringSubmatch(msg)[1]
	case msg == ErrCanceled.Error():
		e.Level, e.Title = LevelCancel, "Đóng hộp thoại bằng Hủy"
	case containsAny(msg, "lỗi", "thất bại", "không chạy được", "broker dừng", "không lấy được", "không đọc được", "exit status"):
		e.Level = LevelError
	case containsAny(msg, "CẢNH BÁO", "từ chối", "bị chặn", "Chưa ", "chưa đồng bộ", "hết hạn"):
		e.Level = LevelWarn
	case containsAny(msg, "Đã ", "đã thêm", "đã thu hồi", "đã đồng bộ", "đã nhập", "đã xóa"):
		e.Level = LevelOK
	}
	if r := []rune(e.Title); len(r) > 160 {
		e.Title = string(r[:159]) + "…"
	}
	return e
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func hexVal(c rune) rune {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// LogDoc is what the log window shows.
type LogDoc struct {
	Sub     string          `json:"sub"`
	Badges  []approve.Badge `json:"badges"`
	Current string          `json:"current"` // Run label of the latest tray start
	Entries []LogEntry      `json:"entries"` // newest first
}

// maxLogEntries caps the table; older entries stay in the raw file.
const maxLogEntries = 2000

// BuildLogDoc parses the log text and counts the latest run's errors and warnings for the badges.
func BuildLogDoc(text, path string, now time.Time) LogDoc {
	es := ParseLog(text)
	doc := LogDoc{Sub: path + " · đọc lúc " + now.Format("15:04:05")}
	if len(es) > 0 {
		doc.Current = es[len(es)-1].Run
	}
	n := map[string]int{}
	cur := 0
	for _, e := range es {
		if e.Run == doc.Current {
			n[e.Level]++
			cur++
		}
	}
	if n[LevelError] > 0 {
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d lỗi", n[LevelError]), Tone: approve.ToneDel})
	} else {
		doc.Badges = append(doc.Badges, approve.Badge{Text: "không lỗi", Tone: approve.ToneAdd})
	}
	if n[LevelWarn] > 0 {
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d cảnh báo", n[LevelWarn]), Tone: approve.ToneMod})
	}
	doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d sự kiện trong lần chạy hiện tại", cur), Tone: approve.ToneMuted})
	if n[LevelCancel] > 0 {
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d lần bấm Hủy", n[LevelCancel]), Tone: approve.ToneMuted})
	}
	if doc.Current != "" {
		doc.Badges = append(doc.Badges, approve.Badge{Text: doc.Current, Tone: approve.ToneMuted})
	}
	if len(es) > maxLogEntries {
		es = es[len(es)-maxLogEntries:]
	}
	for i, j := 0, len(es)-1; i < j; i, j = i+1, j-1 {
		es[i], es[j] = es[j], es[i]
	}
	doc.Entries = es
	return doc
}
