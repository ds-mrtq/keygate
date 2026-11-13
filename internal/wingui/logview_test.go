package wingui

import (
	"strings"
	"testing"
	"time"
)

func TestParseLog(t *testing.T) {
	text := strings.Join([]string{
		"[broker] đã khóa", // before timestamps existed
		"2026-11-12 14:20:00 [tray] icon khay sẵn sàng (icon: png)",
		"2026-11-12 14:20:01 [broker] đã mở khóa (thiết bị dev_abc)",
		`2026-11-12 14:21:00 [tray] hộp thoại lỗi: exit status 1: #< CLIXML`,
		`<Objs><S S="Error">Cannot find_x000D__x000A_</S><S S="Error">type &amp; X</S></Objs>`,
		"2026-11-12 14:22:00 [tray] người dùng hủy",
	}, "\n")
	doc := BuildLogDoc(text, "broker.log", time.Now())
	es := doc.Entries
	if len(es) != 5 {
		t.Fatalf("entries: %+v", es)
	}
	if es[0].Level != LevelCancel || es[4].Level != LevelLock || es[4].Time != "" {
		t.Fatalf("order/levels: %+v", es)
	}
	ps := es[1]
	if ps.Level != LevelError || !strings.Contains(ps.Detail, "Cannot find") || !strings.Contains(ps.Detail, "type & X") || strings.Contains(ps.Detail, "CLIXML") {
		t.Fatalf("clixml: %+v", ps)
	}
	if es[2].Title != "Mở khóa vault (thiết bị dev_abc)" || es[2].Time != "12/11 14:20:01" || es[2].Run != "Lần chạy từ 12/11/2026 14:20" {
		t.Fatalf("unlock: %+v", es[2])
	}
	if es[4].Run == doc.Current || !strings.Contains(doc.Badges[0].Text, "1 lỗi") {
		t.Fatalf("runs/badges: current=%q badges=%+v", doc.Current, doc.Badges)
	}
}
