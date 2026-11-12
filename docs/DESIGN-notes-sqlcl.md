# Ghi chú SQLcl: chế độ hạn chế `-R` (H2)

Đo thực tế ngày 2026-11-10 trên máy laptop: SQLcl 26.3 (`sql.exe`), `JAVA_HOME` = `C:/Program Files/Eclipse Adoptium/jdk-21.0.10.7-hotspot`, stdin là file (`< e.sql`), kết nối `/nolog` (chưa thử với DB thật). Script thử `t.sql` lần lượt chạy `host`, `!`, `script` (JS), `spool file`, `@inc.sql`, `@@inc.sql`, `start inc.sql`; script `u.sql` (`prompt A`, `@inc.sql`, `prompt B`) nạp bằng đối số dòng lệnh `@u.sql`.

| Mức | `host` | `!` | `script` (JS) | `spool` ra file | `@`/`@@`/`start` trong script | `@u.sql` trên dòng lệnh | ghi chú |
|---|---|---|---|---|---|---|---|
| 1 | chặn (SP2-0738) | chặn | **chạy** (máy này chưa có GraalVM JS nên báo "JavaScript engine not found"; cài GraalVM thì chạy được) | **chạy**, ghi file | chạy | chạy | |
| 2 | chặn | chặn | **chạy** (như mức 1) | chặn | chạy | chạy | |
| 3 | chặn | chặn | **chạy** (như mức 1) | chặn | chặn | chạy (script cấp trên chạy, `@` lồng bên trong bị chặn) | |
| 4 | chặn | chặn | **chặn** | chặn | chặn | chạy (script cấp trên chạy, `@` lồng bên trong bị chặn) | lệnh `exit` cũng bị chặn: phiên kết thúc khi hết stdin/script |

Kết luận:

- Mức thấp nhất vừa cho `@file.sql` vừa chặn `host` là 1, nhưng mức 1-3 vẫn cho `script` (JS gọi được Java: đọc wallet) và mức 1 cho `spool` ghi file tùy ý. Mức duy nhất chặn cả `host`, `!`, `script`, `spool` là **4**.
- Ở mức 4 vẫn nạp được **một** script cấp trên qua đối số `@file.sql` (đã đo), chỉ `@` lồng bên trong bị chặn. Vì vậy broker **luôn chèn `-R 4`** ngay sau tên chương trình cho `sql`/`sqlcl` và từ chối mọi đối số `-R`/`-RESTRICT` do request tự đưa vào. Cần `@` lồng nhau thì phải gộp script thành một file.
- `sqlplus`: chưa có trên máy đo (chưa đo). Broker chèn `-R 3` (mức cao nhất của SQL*Plus, chặn `host`/`edit`/`spool`/`get`/`start`/`@` lồng); chưa kiểm `@file` cấp trên ở mức này.
- Ranh giới còn lại: script cấp trên do policy cho phép (mẫu `@path:…`) vẫn là mã tin cậy theo policy; nội dung nó in ra đi qua redactor; `connect` và truy vấn SQL không bị `-R` chặn nên một script được phép vẫn có thể `select` rồi in giá trị (đã nằm trong rủi ro còn lại của PRD).
- Mẫu allow đề xuất: `"sql /@HTTEST @path:D:/repos/x/sql/**/*.sql"` (alias cố định + script nằm trong thư mục tin cậy; thêm `!exact` nếu không cho tham số thừa).
