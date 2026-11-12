# KeyGate

**A secret broker for AI coding agents.** Agents run commands that need passwords, API tokens or Oracle wallets without ever reading the values. A local broker holds the vault key in RAM, checks a pinned policy, asks you (Windows Hello or a paired phone) and runs the command itself, masking every secret in the output as `[kg:<name>]`.

> Tài liệu chi tiết viết bằng tiếng Việt. Docs below are in Vietnamese.

**Kho khóa cho AI agent.** Agent (Claude Code, omp, hoặc agent bất kỳ có hook PreToolUse/MCP) chạy được lệnh cần mật khẩu, token, wallet Oracle mà không bao giờ thấy giá trị. Mỗi lần dùng, bạn là người gật đầu.

- Trang giới thiệu cho người không chuyên: [`docs/guide/gioi-thieu.html`](docs/guide/gioi-thieu.html)
- Hướng dẫn sử dụng có sơ đồ: [`docs/guide/index.html`](docs/guide/index.html)
- Tham chiếu lệnh: [`docs/CLI.md`](docs/CLI.md) · Thiết kế mật mã, định dạng file, relay: [`docs/DESIGN.md`](docs/DESIGN.md)

## Có gì

- `kg`: CLI + broker viết bằng Go (chỉ stdlib, `golang.org/x/crypto`, `golang.org/x/sys`). `kgw tray`: broker dạng icon khay hệ thống trên Windows.
- Vault mã hóa XChaCha20-Poly1305, mỗi thiết bị một log chỉ ghi thêm, sự kiện thành viên ký Ed25519, khôi phục bằng mật khẩu chủ + khóa giấy.
- Policy ghim bằng hash: secret nào, chương trình nào, mẫu tham số nào, kiểu duyệt nào. Secret PROD bị từ chối mặc định.
- Chạy lệnh: secret vào biến môi trường, file tạm hoặc wallet Oracle tạm; đầu ra che giá trị nguyên văn, base64, URL-encode.
- Hook chặn agent đọc `.env`, `cwallet*`, dump biến môi trường; MCP server (`list_secrets`, `request_grant`, `run_with_secret`), không tool nào trả giá trị.
- Relay đồng bộ trên Cloudflare Workers Free (Durable Object SQLite), chỉ lưu bản mã và dòng đã ký. PWA trên điện thoại để duyệt từ xa qua Web Push.
- Audit chuỗi hash + MAC, phát hiện cắt đuôi/xóa.

## Build và chạy thử

```bash
go build -o kg ./cmd/kg
go test -count=1 -tags kgtest ./...
kg init --label laptop
kgw tray            # Windows; nơi khác: kg broker
kg run --secret db/test/app -- sql /@ebs_test @D:/repos/x/sql/check.sql
```

Relay: xem [`relay/README.md`](relay/README.md) (`npx wrangler deploy`, điền `ALLOWED_VAULTS` bằng ID vault của bạn, sinh khóa VAPID bằng `node scripts/vapid.mjs` nếu dùng Web Push).

## Trạng thái và giới hạn

- Dự án cá nhân, dùng hằng ngày trên Windows 11 + iPhone. Duyệt Touch ID trên macOS chưa kiểm trên máy thật; Linux dùng mật khẩu thiết bị và duyệt `device`.
- Chưa có kiểm toán bảo mật độc lập. Các rủi ro còn lại đã biết ghi trong `docs/DESIGN.md` và `docs/CLI.md`: redactor không che hex, UTF-16, chuỗi đảo, giá trị dưới 4 ký tự; khe TOCTOU giữa lúc băm script và lúc chạy; khôi phục cặp `policy.yaml` + pin cũ trước khi broker khởi động không bị phát hiện; tài khoản Cloudflare phục vụ PWA là một phần gốc tin cậy cho quyền duyệt.
- Báo lỗi bảo mật: mở issue không kèm chi tiết khai thác, hoặc liên hệ qua GitHub.

## License

[MIT](LICENSE)
