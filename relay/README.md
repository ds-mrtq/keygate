# KeyGate relay

Relay đồng bộ cho KeyGate: một Cloudflare Worker + Durable Object `VaultDO` (mỗi vault một DO, lưu bằng SQLite storage API). Không có dependency runtime; `wrangler`, `typescript`, `@cloudflare/workers-types` chỉ là devDependency. Class `VaultDO` khai báo trong `wrangler.toml` bằng `new_sqlite_classes`, nên chạy được trên gói Workers Free.

Hợp đồng đầy đủ: `docs/DESIGN.md` mục 8.

## Triển khai

```
cd relay
npm install
npx wrangler login        # một lần
# sửa wrangler.toml: ALLOWED_VAULTS = "vlt_abc123,vlt_other"
npx wrangler deploy
```

`ALLOWED_VAULTS` (danh sách ID vault phân tách bằng dấu phẩy, mục `[vars]` trong `wrangler.toml`) là allowlist bắt buộc: Worker trả 403 cho mọi vault không có trong danh sách, **trước khi** tạo Durable Object. Để trống = không phục vụ vault nào. ID vault lấy từ `vault.json` sau `kg init`; thêm ID rồi `wrangler deploy` lại (hoặc đặt biến trong dashboard Cloudflare).

Lệnh `deploy` in URL dạng `https://keygate-relay.<tài-khoản>.workers.dev`. Đặt URL đó vào `vault.json` (`relay_url`) trên mỗi máy.

Chạy thử cục bộ (state phải trống):

```
rm -rf .wrangler/state
npx wrangler dev --port 8787 --var ALLOWED_VAULTS:vlt_smoke_local
node test/smoke.mjs        # ở terminal khác (30 kiểm tra)
```

## API

```
PUT  /v/{vault}/log/{device}/{seq}     body = 1 dòng JSON; seq đã có -> 409; seq != cuối+1 -> 400
GET  /v/{vault}/log?since=dev_a:12,dev_b:3   tối đa 2000 dòng/lần, "more":true nếu còn -> gọi lại với since mới
PUT  /v/{vault}/members/{n}            n đã có -> 409; n nhảy cóc / sai chữ ký owner / sai prev -> 400
GET  /v/{vault}/members?since=n
PUT  /v/{vault}/checkpoint/{device}    ghi đè; members_n hoặc seen[dev] lùi so với bản đang lưu -> 422
GET  /v/{vault}/checkpoints
GET  /v/{vault}/ws                     WebSocket, server gửi "new" khi có ghi (hibernatable)
```

Header mọi request: `KG-Device`, `KG-Time`, `KG-Sig`.
- `KG-Time`: RFC3339 UTC (có thể kèm mili giây), lệch quá 5 phút -> 401, và **phải lớn hơn hẳn** `KG-Time` cuối cùng relay đã nhận từ cùng `KG-Device` (chống phát lại; client Go tự giữ đơn điệu tăng theo ms).
- `KG-Sig` = base64 Ed25519 trên `"kg/v1/relay-req\x00" + lp(method) + lp(path_with_query) + lp(time) + lp(sha256_hex(body))`.

GET trả: `{"logs":{"dev":[{"seq":1,"line":"…"}]},"more":false}`, `{"members":[{"n":0,"line":"…"}]}`, `{"checkpoints":{"dev":"…"}}`.

### Xác thực và kiểm tra ở relay (chỉ để chặn rác; máy nhận vẫn tự kiểm tất cả)

- Route ghép điện thoại (schema v4): `PUT pair-open/{code16}` (ký, thiết bị đầy đủ, mở khe 10 phút, mỗi thiết bị một khe), `PUT pair/{code16}` (không ký, chỉ điền khe đã mở, 404 nếu không có khe, 409 nếu đã điền), `GET pair/{code16}` (ký, chỉ thiết bị đã mở: 204 chưa điền, 200 rồi xóa khe). Chi tiết ở DESIGN §8.
- Worker (không trạng thái) từ chối trước khi chạm DO: vault ngoài allowlist (403), route lạ (404), PUT thiếu `Content-Length` (411) hoặc > 64 KiB (413), header/chữ ký sai định dạng hoặc lệch giờ (401).
- Mỗi sự kiện thành viên được kiểm: chữ ký owner trên canonical đúng DESIGN 4.2 (`"kg/v1/member\x00"+u64(v)+lp(vault)+u64(n)+lp(prev)+lp(type)+lp(body)`) và `prev` = `sha256:`+hex(sha256(canonical||sig)) của sự kiện n-1. Sai -> 400. Trạng thái xác thực (thiết bị, thu hồi) chỉ suy ra từ sự kiện đã kiểm; `revoke` chỉ cần `dev` trong body.
- Genesis (`PUT members/0` khi vault rỗng): request ký bằng `owner_pub` trong chính genesis (`KG-Device: owner`), sự kiện tự ký bằng `owner_pub`. Các bảng chỉ được tạo sau khi genesis được chấp nhận.
- Khóa công khai: thiết bị từ sự kiện `add` (chưa bị `revoke`), cộng khóa owner (`KG-Device: owner`). Owner được ghi `members` và **đọc** log/members/checkpoints (khôi phục từ relay không cần `--members-file`); owner không được ghi log/checkpoint.
- `PUT log/{device}` và `PUT checkpoint/{device}` chỉ do chính `{device}` ký (khác -> 403).
- `log`, `members` chỉ INSERT. `checkpoint` ghi đè nhưng không được lùi.
- Giới hạn mỗi vault: 200.000 dòng, 200 MB -> 507. Số trong đường dẫn tối đa 15 chữ số.

## Rate limiting (nên bật)

Đường dẫn vault là ID ngẫu nhiên, nhưng nên chặn thêm ở tầng Cloudflare. Trong dashboard: Security -> WAF -> Rate limiting rules (hoặc gắn custom domain rồi tạo rule):

- Điều kiện: `URI Path starts with "/v/"` (và hostname = hostname relay).
- Đếm theo IP, ví dụ 60 request / 1 phút; hành động Block 10 phút.
- Gợi ý phụ: rule riêng cho `PUT` với ngưỡng thấp hơn (30 / 1 phút).

Worker đã từ chối request không ký đúng, nhưng rule trên giảm chi phí request rác và giới hạn dò ID vault.

## Cloudflare thấy gì

Thấy: ID vault (ngẫu nhiên), ID thiết bị và nhãn thiết bị (nằm rõ trong sự kiện `add`), số lượng/kích thước/thời điểm của bản ghi, địa chỉ IP và thời điểm kết nối của máy bạn, khóa công khai Ed25519/X25519 của thiết bị và owner, cấu trúc chuỗi bản ghi (`item`, `parent`, `seq`, `prev`, `epoch`).

Không thấy: giá trị secret, tên secret, mô tả, tag, môi trường (tất cả nằm trong `ct` mã hóa XChaCha20-Poly1305), vault key, khóa riêng của thiết bị/owner, mật khẩu chủ, khóa giấy.

Worker không lưu và không nhận bất kỳ cấu hình bí mật nào (không có secret binding, không biến môi trường nhạy cảm). Nếu Cloudflare hoặc kẻ tấn công sửa/xóa/giấu dữ liệu, máy nhận phát hiện qua chữ ký, chuỗi `prev`, high-water mark và checkpoint (DESIGN mục 5); relay chỉ có thể làm mất tính sẵn sàng, không làm lộ hay giả mạo nội dung.
