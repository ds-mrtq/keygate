# KeyGate: thiết kế triển khai v1

Nguồn yêu cầu: PRD bản nháp 0.4 (10/11/2026, tài liệu nội bộ, không kèm repo). File này là hợp đồng kỹ thuật cho mã nguồn; chỗ nào khác PRD có ghi lý do.

## 1. Ràng buộc chung

- Go 1.25, module `keygate`. Dependency chỉ được: thư viện chuẩn, `golang.org/x/crypto`, `golang.org/x/sys`. Không thêm thư viện khác (kể cả YAML, QR, CLI framework).
- Relay: TypeScript trên Cloudflare Workers, không dependency runtime; `wrangler` chỉ là devDependency.
- Không lệnh nào in giá trị secret ra stdout/stderr trừ `kg reveal` (luôn đòi duyệt người, bị hook chặn với agent).
- Hỏng an toàn: thiếu chữ ký, sai chuỗi, broker không chạy, policy lệch pin → từ chối, mã thoát khác 0.

## 2. Mật mã (`internal/kcrypto`)

| Việc | Thuật toán |
|---|---|
| Mã hóa item | XChaCha20-Poly1305 (`chacha20poly1305.NewX`), nonce 24 byte ngẫu nhiên |
| Ký | Ed25519 |
| Bọc khóa | X25519 ECDH(ephemeral, recipient) → HKDF-SHA256 → XChaCha20-Poly1305 |
| Mật khẩu | Argon2id, t=3, m=64 MiB, p=4, salt 16 byte |
| Dẫn xuất | HKDF-SHA256 |

Domain separation: mọi chuỗi đem ký/MAC/HKDF bắt đầu bằng nhãn ASCII kết thúc `\x00`:

| Nhãn | Dùng cho |
|---|---|
| `kg/v1/record` | chữ ký bản ghi item |
| `kg/v1/member` | chữ ký sự kiện thành viên |
| `kg/v1/checkpoint` | chữ ký checkpoint |
| `kg/v1/relay-req` | chữ ký request tới relay |
| `kg/v1/approval` | chữ ký duyệt từ thiết bị khác |
| `kg/v1/item-key` | HKDF info khóa item |
| `kg/v1/wrap` | HKDF info bọc vault key |
| `kg/v1/recovery` | HKDF dẫn xuất recovery seed |
| `kg/v1/local-mac` | HKDF khóa MAC trạng thái cục bộ (seen, policy pin, audit) |

Mã hóa length-prefixed `lp(x)` = uint32 big-endian độ dài + byte. Số nguyên mã hóa uint64 big-endian 8 byte. `null`/rỗng = độ dài 0.

- Khóa item: `HKDF(ikm=vaultKey[epoch], salt=nil, info="kg/v1/item-key\x00"+lp(vault)+u64(epoch)+lp(item))` → 32 byte.
- Bọc vault key cho người nhận: `eph` X25519 mới; `shared=X25519(eph_priv, rcpt_pub)`; `k=HKDF(shared, salt=nil, info="kg/v1/wrap\x00"+lp(vault)+u64(epoch)+lp(eph_pub)+lp(rcpt_pub))`; `ct=XChaCha(k, nonce, vaultKey, aad=info)`. Lưu `{rcpt, eph, nonce, ct}` (base64 std).

## 3. Khóa và vai trò

- **Khóa thiết bị**: mỗi máy một cặp Ed25519 (ký) + một cặp X25519 (nhận bọc khóa). ID `dev_<10 ký tự base32 ngẫu nhiên thường>`. Nhãn thiết bị (vd `laptop`) nằm rõ trong sự kiện thành viên, vì kênh đồng bộ đằng nào cũng thấy ID thiết bị; nhãn không được chứa tên hệ thống hay tên secret.
- Khóa riêng thiết bị lưu: Windows DPAPI (`CryptProtectData`, scope user) → `device.key.dpapi`; macOS Keychain qua `/usr/bin/security add/find-generic-password` (service `keygate`, account `<dev>`); Linux file `device.key.enc` quyền 600, mã bằng Argon2id(mật khẩu mở khóa thiết bị). Interface `devkey.Store{Save, Load}` chọn theo `runtime.GOOS`; backend `plain` (`KG_DEVKEY_BACKEND=plain`) chỉ có trong bản build `-tags kgtest`, bản phát hành bỏ qua biến này.
- **Recovery seed** = `HKDF(ikm=Argon2id(masterPwd, salt) || paperKey, salt=nil, info="kg/v1/recovery\x00"+lp(vault))` → 64 byte: 32 byte đầu là seed Ed25519 **owner key**, 32 byte sau là X25519 **recovery key**. `paperKey` 32 byte ngẫu nhiên, in cho người dùng dạng base32 nhóm 4 ký tự + checksum (CRC32 4 ký tự cuối). Salt Argon2id nằm trong sự kiện genesis.
  - Khác PRD: PRD không định nghĩa owner key. Lý do chọn: mất laptop thì vẫn ký được thu hồi; đồng thời relay/git không thể brute-force mật khẩu chủ offline vì thiếu paperKey 256-bit.
  - Hệ quả: thao tác owner (thêm thiết bị, thu hồi thiết bị đầy đủ, tăng epoch, khôi phục) đòi nhập mật khẩu chủ **và** khóa giấy. Thu hồi thiết bị duyệt là ngoại lệ: `revoke-approver` ký bằng khóa thiết bị đầy đủ sau Windows Hello (mục 4.2).
- **Vault key** theo epoch: 32 byte ngẫu nhiên. Mỗi epoch được bọc cho mọi thiết bị đang là thành viên và cho recovery public key, đặt trong sự kiện `epoch` của `members.kgl`.
- **Giới hạn đã chấp nhận (ghi 12/11/2026, rà soát A3)**: khóa thiết bị trên Windows bọc DPAPI scope user, entropy là ID thiết bị (công khai). Mọi tiến trình chạy cùng user Windows, kể cả agent AI mà KeyGate muốn kiểm soát, gọi được `CryptUnprotectData` để lấy khóa thiết bị, gỡ bọc vault key theo epoch và đọc toàn bộ `log/*.kgl` mà không qua broker; cùng khóa đó sinh `LocalMacKey` nên cũng giả được MAC của `grants.json`, `policy.pin`, `members.mac`, audit. Broker, grant, ghim hash và che đầu ra vì vậy chỉ là ma sát + dấu vết với tác nhân cùng user, không phải ranh giới cứng (PRD: "mã độc chiếm quyền người dùng" ngoài phạm vi). Hướng dài hạn: broker chạy bằng tài khoản Windows riêng (service), `KG_HOME` và named pipe có ACL chỉ cho user người dùng kết nối; khay và Windows Hello ở phiên người dùng gọi sang. Chưa làm.

## 4. Định dạng file (thư mục `KG_HOME`, mặc định `~/.keygate`)

```
KG_HOME/
  device.json              # {dev, label, ed_pub, x_pub} – công khai
  device.key.dpapi|.enc    # khóa riêng thiết bị (theo backend)
  vault.json               # {vault, relay_url?, git_dir?, sync_dir?} – công khai
  members.kgl              # JSONL sự kiện thành viên, owner ký
  log/<dev>.kgl            # JSONL bản ghi item, mỗi thiết bị một file, chỉ ghi thêm
  checkpoints/<dev>.json   # checkpoint mới nhất của từng thiết bị
  state/local.json         # high-water seq từng thiết bị + số sự kiện members, MAC bằng local-mac key
  audit/ledger.jsonl       # audit chuỗi hash, MAC từng dòng
  policy.yaml              # policy (không chứa secret)
  state/policy.pin         # sha256 policy + MAC
  broker.sock              # AF_UNIX socket của broker (Windows 10+ cũng có AF_UNIX)
```

### 4.1 Bản ghi item (`log/<dev>.kgl`, một JSON mỗi dòng)

Đúng PRD mục 06, thêm `merge` (tùy chọn) để giải xung đột:

```json
{"v":1,"vault":"vlt_…","item":"itm_…","parent":"sha256:…"|null,"merge":["sha256:…"],"dev":"dev_…","seq":128,"prev":"sha256:…"|null,"epoch":3,"op":"put"|"tombstone","nonce":"b64","ct":"b64","sig":"b64"}
```

- Canonical ký: `"kg/v1/record\x00" + u64(v) + lp(vault) + lp(item) + lp(parent) + u64(len(merge)) + lp(m_i)… + lp(dev) + u64(seq) + lp(prev) + u64(epoch) + lp(op) + lp(nonce_raw) + lp(ct_raw)`.
- `sig = Ed25519(dev_priv, canonical)`.
- `record_hash = "sha256:" + hex(sha256(canonical || sig_raw))` (có cả chữ ký). Dùng cho `parent`, `merge`, `prev`.
- AAD của `ct` = `"kg/v1/record\x00" + lp(vault) + lp(item) + lp(parent) + u64(epoch) + lp(dev) + u64(seq)`.
- `op=tombstone`: `ct` vẫn là bản mã của `{"name": …}` (để biết tên item đã xóa), không có `value`.
- Plaintext (JSON trước khi mã hóa): `{"name","value","desc","tags":[],"env":"test|dev|prod|…","kind":"env|file|oracle-wallet|template","env_name","tns_alias","user","file_ext"}`. Với `oracle-wallet`: `user` + `value`=mật khẩu.
- `seq` bắt đầu 1, liên tục; `prev` của seq 1 là null.
- `item` ID ngẫu nhiên `itm_<16 base32>`; tên secret chỉ nằm trong `ct`.

### 4.2 Sự kiện thành viên (`members.kgl`)

```json
{"v":1,"vault":"vlt_…","n":0,"prev":null|"sha256:…","type":"genesis|add|revoke|epoch|revoke-approver","body":{…},"sig":"b64"}
```

- Trường `body` là base64 std của byte JSON gọn (`json.Marshal` struct có thứ tự trường cố định). Canonical: `"kg/v1/member\x00" + u64(v) + lp(vault) + u64(n) + lp(prev) + lp(type) + lp(body_bytes)`, trong đó `body_bytes` là byte sau khi giải base64; nhờ vậy byte ký không phụ thuộc bộ phân tích JSON.
- Ký bằng owner key, trừ `revoke-approver` (xem dưới). `hash = sha256(canonical||sig)`.
- `genesis.body`: `{owner_pub, recovery_pub, argon_salt, argon_params, created}`.
- `add.body`: `{dev, label, ed_pub, x_pub}`.
- `revoke.body`: `{dev, reason, last_seq, last_hash}`; `last_hash` = `record_hash` của bản ghi thiết bị đó tại `last_seq` (rỗng khi `last_seq`=0). Phải theo sau ngay bằng một `epoch` mới. `kg device revoke` sync trước rồi mới lấy `last_seq`.
- `revoke-approver.body`: `{dev, by, reason}` (thêm 12/11/2026). Thu hồi một thiết bị duyệt (`role: approver`), ký bằng khóa Ed25519 của thiết bị `by`, không phải owner key. Điều kiện: `by` là thiết bị đầy đủ còn hoạt động; `dev` là thiết bị duyệt còn hoạt động; `reason` ≤ 256 byte. Không có `epoch` theo sau, không mã hóa lại: thiết bị duyệt chưa từng nhận bản bọc vault key và không ghi bản ghi. Laptop, relay (`putMember`) và PWA (`verifyMembers`) cùng kiểm. Lý do: thu hồi điện thoại chỉ cần Windows Hello tại máy, không cần mật khẩu chủ + khóa giấy. Đánh đổi: ai vượt được Hello trên một thiết bị đầy đủ thì thu hồi được điện thoại (chỉ giảm quyền, không lộ secret). Thu hồi thiết bị đầy đủ và thêm thiết bị vẫn cần owner key.
- `epoch.body`: `{epoch, wraps:[{rcpt:"dev_…"|"recovery", eph, nonce, ct}]}`; epoch 1 nằm ngay sau genesis + add thiết bị đầu.
- Thành viên tại thời điểm X = replay genesis..X. Bản ghi item của thiết bị bị thu hồi: chấp nhận seq ≤ `last_seq` và bản ghi tại `last_seq` phải có đúng `last_hash` (lệch → `ErrBrokenChain`); bản ghi seq > `last_seq` bị **bỏ qua** (không lưu, không làm hỏng cả lô), để thiết bị đã thu hồi không chặn được đồng bộ của máy khác. Checkpoint do thiết bị đã thu hồi ký bị bỏ qua.

### 4.3 Checkpoint

`{"v":1,"vault","dev","time","members_n","seen":{"dev_…":seq,…},"sig"}`; canonical `"kg/v1/checkpoint\x00"+u64(v)+lp(vault)+lp(dev)+lp(time)+u64(members_n)+` các cặp `lp(dev)+u64(seq)` sắp theo dev tăng dần. Ký bằng khóa thiết bị.

## 5. Kiểm tra khi đọc (FR-11, bộ tấn công 5/5)

Khi nạp từ bất kỳ kênh nào, máy nhận tự kiểm tất cả, coi như relay không kiểm gì:

| Tấn công | Phát hiện | Lỗi |
|---|---|---|
| Sửa nội dung bản ghi | chữ ký Ed25519 sai | `ErrBadSignature` |
| Chèn thiết bị lạ | `dev` không có trong members (hoặc members event sai chữ ký owner; `revoke-approver` sai chữ ký thiết bị `by`) | `ErrUnknownDevice` |
| Xóa bớt bản ghi giữa log | `prev` không khớp hash bản trước hoặc seq nhảy | `ErrBrokenChain` |
| Tua lùi | seq cao nhất của kênh < high-water trong `state/local.json` | `ErrRollback` |
| Giấu cập nhật | checkpoint hợp lệ của thiết bị khác ghi `seen[X]` > seq của X đang có | `ErrHidden` |

Bản ghi hỏng không bao giờ được ghi vào log cục bộ. Log cục bộ chỉ ghi thêm; bản ghi nhận về phải nối tiếp đúng chuỗi của log cục bộ cùng thiết bị (fork trong log một thiết bị = `ErrBrokenChain`). `parent`/`merge` chỉ được trỏ tới bản ghi cùng `item`. Bộ phân tích nghiêm ngặt: JSON phải trùng byte với bản `json.Marshal` lại (chặn khóa trùng, khác hoa/thường), base64 không chứa CR/LF. Nhiều tiến trình ghi cùng `KG_HOME` phải giữ file khóa `KG_HOME/lock`.

**Ghim genesis (chống kênh giả vault khi máy mới tham gia):** `GenesisPin` = base32 (nhóm 4 ký tự) của 15 byte đầu `sha256(genesis_hash || vault)`, 120 bit. `kg device add` và `kg status` in ghim; máy mới `kg join` bắt buộc nhập `--vault` và `--pin`, lệch → `ErrPin`. Vault ID không bao giờ lấy từ kênh.

## 6. Gộp và xung đột (FR-12)

- Theo từng `item`: đồ thị bản ghi qua `parent` + `merge`. Head = bản ghi không bị bản nào trỏ tới.
- 1 head: `put` → item sống; `tombstone` → đã xóa.
- ≥ 2 head: trạng thái **xung đột**; giữ mọi head; broker từ chối cấp item này (`ErrConflict`). `kg conflicts` liệt kê (tên, thiết bị, thời điểm – không giá trị); `kg resolve-conflict <name> --keep <dev|hash>` ghi bản ghi mới `parent=<head chọn>`, `merge=[các head còn lại]`.
- Sau khi tăng epoch, thiết bị thực hiện ghi lại mọi item sống bằng epoch mới (`parent` = head hiện tại).

## 7. Đồng bộ (`kg sync`)

Interface `transport.Transport { Pull(ctx, since map[dev]seq) ([]Line, members []Line, cps []Checkpoint, error); Push(ctx, lines, members, cp) error }`.

- `dir`: thư mục chung (Syncthing, USB, ổ mạng). Cấu trúc giống `KG_HOME` (chỉ `members.kgl`, `log/`, `checkpoints/`). Máy chỉ ghi file của chính mình (`log/<dev>.kgl`, `checkpoints/<dev>.json`); `members.kgl` chỉ ghi khi thêm sự kiện owner.
- `git`: `dir` + `git pull --rebase` / `git add` / `git commit` / `git push` trong repo chỉ định. `kg sync --verify-via git`: lấy trạng thái qua git, so fingerprint với trạng thái nhận qua relay, khác thì báo `ErrFork`.
- `relay`: HTTP theo mục 8.
- Sau mỗi sync thành công: ghi checkpoint của mình, cập nhật `state/local.json`.
- `kg fingerprint`: 6 từ từ `sha256(members head || sắp xếp (dev, head hash))`, mỗi từ 8 bit từ danh sách 256 từ cố định.

## 8. Relay (Cloudflare Worker + Durable Object SQLite)

API (PRD 07b):

```
PUT  /v/{vault}/log/{device}/{seq}     # body = 1 dòng JSON bản ghi; seq đã có → 409
GET  /v/{vault}/log?since=dev_a:12,dev_b:3
PUT  /v/{vault}/members/{n}            # body = sự kiện thành viên; n đã có → 409
GET  /v/{vault}/members?since=n
PUT  /v/{vault}/checkpoint/{device}    # ghi đè checkpoint mới nhất của thiết bị
GET  /v/{vault}/checkpoints
GET  /v/{vault}/ws                     # WebSocket: server gửi "new" khi có ghi
PUT  /v/{vault}/pair-open/{code16}      # ký, thiết bị đầy đủ: mở khe ghép 10 phút (code16 = 16 ký tự A-Z2-7, 80 bit)
PUT  /v/{vault}/pair/{code16}          # KHÔNG ký (điện thoại chưa có khóa): chỉ điền vào khe đã mở, chưa điền
GET  /v/{vault}/pair/{code16}          # ký, chỉ thiết bị đã mở khe: 204 chưa điền, 200 + xóa khe, 404 không có/hết hạn
```

Header: `KG-Device`, `KG-Time` (RFC3339 UTC, lệch > 5 phút → 401), `KG-Sig` = base64 Ed25519 trên `"kg/v1/relay-req\x00"+lp(method)+lp(path_with_query)+lp(time)+lp(sha256_hex(body))`.

- Durable Object `VaultDO` mỗi vault: bảng `members(n PK, body, dev_pub_ed)` , `log(dev, seq, body, PK(dev,seq))`, `checkpoints(dev PK, body)`. Chỉ INSERT với `log`/`members`; không UPDATE, không DELETE.
- Worker chỉ phục vụ vault có trong biến `ALLOWED_VAULTS` (kiểm ở Worker, trước khi chạm Durable Object); chặn theo `Content-Length` (> 64 KiB) và header/thời gian trước DO; giới hạn mỗi vault 200k dòng / 200 MB.
- Worker kiểm chữ ký request: khóa công khai thiết bị lấy từ các sự kiện `add` **đã kiểm chữ ký owner và chuỗi `prev`** trong bảng members; `PUT members/0` (genesis) chấp nhận khi vault rỗng và request ký bằng `owner_pub` trong chính genesis. Worker kiểm chữ ký owner (`revoke-approver`: chữ ký thiết bị `by` đang là thiết bị đầy đủ, đích đang là thiết bị duyệt, sự kiện trước không phải `revoke` chờ epoch, dòng và thân ở dạng chuẩn, kiểm lại trong đoạn đồng bộ) + chuỗi `prev` của mọi sự kiện thành viên trước khi lưu (khác bản đầu: trước đây không kiểm; đổi vì sự kiện rác chiếm chỉ số `n` sẽ chặn vĩnh viễn việc thu hồi). Request ký bằng owner (`KG-Device: owner`) được ghi members và đọc (phục vụ khôi phục từ relay).
- Chống phát lại: `KG-Time` mỗi thiết bị phải tăng ngặt; checkpoint không được lùi `members_n`/`seen`. `seq` tối đa 15 chữ số, `PUT log` phải đúng seq kế tiếp; `GET log` phân trang 2000 dòng.
- Nguồn thiết bị (thêm 12/11/2026, schema v3): Worker gắn header `KG-Origin` = base64 JSON `{ip, country, city, org, ua}` lấy từ `CF-Connecting-IP`, `request.cf` và `User-Agent` (ghi đè header client gửi) trước khi chuyển cho DO. DO lưu nguồn của `PUT pair` (cột `pairslot.meta`, trả lại ở header `KG-Pair-Origin` của `GET pair`) và của request có chữ ký gần nhất mỗi thiết bị (bảng `seen(dev PK, t, meta)`). `GET /v/{vault}/devices` (chỉ thiết bị đầy đủ) trả danh sách đó. Dữ liệu này không có chữ ký, chỉ để hiển thị (cột "Nguồn lúc ghép", "Hoạt động gần nhất"); nguồn lúc ghép được laptop chép vào audit `device-add` (argv thứ 4).
- Khe ghép (schema v4, 12/11/2026, sửa R1): bảng `pairslot(code PK, opener, exp, body, meta)` thay bảng `pair` không ký cũ (bị xóa), bỏ giới hạn 50 mã chung. `PUT pair-open` chỉ do thiết bị đầy đủ đang hoạt động ký (không phải owner, không phải điện thoại duyệt; 403), xóa khe hết hạn và khe cũ của chính thiết bị đó (mỗi thiết bị một khe), hết hạn sau 10 phút, trùng mã → 409. `PUT pair` không ký chỉ được điền khe tồn tại, còn hạn, chưa có body (không có/hết hạn → 404, đã điền → 409, body ≤ 1024 byte); kẻ biết vault ID + URL không còn chiếm được chỗ của laptop vì không có khe thì không ghi được gì. `GET pair` chỉ trả cho đúng thiết bị đã mở (thiết bị khác → 404), body rỗng → 204, có body → 200 kèm `KG-Pair-Origin` rồi xóa khe.
- Phía client: `transport.ErrExists` → kéo lại dòng trên kênh, so từng byte; khác → `ErrForkChannel`, không đánh dấu đã đẩy.
- Đường dẫn vault là ID ngẫu nhiên; README relay có hướng dẫn rule rate limiting.

## 9. Broker, grant, duyệt (FR-03, FR-06, FR-09)

- `kg broker` chạy foreground trong terminal của người dùng (hoặc Task Scheduler lúc logon). **Không** tự khởi động từ `kg run`. Socket `KG_HOME/broker.sock`.
- Mở khóa: lúc start và sau khi tự khóa, cần duyệt người (Windows Hello / Touch ID / mật khẩu thiết bị trên Linux nhập ở TTY của broker). Vault key chỉ nằm trong RAM broker. **Mặc định không tự khóa**: không khóa khi rảnh, không khóa khi khóa màn hình (Win+L không đổi gì với agent); vault chỉ khóa khi `kg lock`/Khóa ở khay hoặc khi broker restart/logoff. Ai muốn chế độ chặt: `kg broker --idle <thời lượng>` (tự khóa khi rảnh) và/hoặc `--lock-on-screen-lock` (Windows kiểm `OpenInputDesktop` mỗi 5 giây), cả hai chỉ áp ngoài phiên làm việc. Broker lắng nghe socket trước rồi mở khóa nền; Hello bị từ chối thì broker vẫn chạy, ở trạng thái khóa.
- Giao thức socket: JSON một dòng mỗi chiều. Lệnh: `list`, `run`, `resolve`, `grant`, `reveal`, `set`, `import`, `policy-apply`, `status`, `lock`. CLI là client mỏng. **Không giá trị secret nào đi qua socket** theo cả hai chiều: `kg set` chỉ gửi metadata, broker hỏi giá trị (ẩn) trên TTY của chính nó; `kg import` gửi đường dẫn, broker tự đọc file sau khi duyệt người; `kg reveal` in giá trị chỉ trên TTY broker. Nhờ vậy socket bị chiếm chỗ cũng không bắt được giá trị.
- `policy.yaml` (PRD mục 05): parser YAML con tự viết, chỉ hỗ trợ đúng cấu trúc này (map lồng nhau 2 cấp, list dạng `[…]`, chuỗi có/không ngoặc, comment `#`).
  ```yaml
  grants:
    <secret-name-or-glob>:
      kind: env|file|oracle-wallet|template
      env_name: …
      tns_alias: …
      allow_commands: ["sql", "python D:/repos/x/*.py"]
      approval: user-presence|device|none|deny
      ttl: 30m
  ```
  Broker chỉ dùng policy khi `sha256(policy.yaml)` khớp `state/policy.pin` (có số phiên bản tăng dần, MAC); `kg policy apply` in diff từng grant trên TTY broker, gắn cờ `approval: none`/wildcard/PROD, xóa grant tạm và grant bền của mục `allow_commands` không còn trong policy mới, cập nhật pin sau khi duyệt người. Lệch pin → từ chối mọi grant (hỏng an toàn). Khối `oracle: {java, pki_jar, tns_admin}` nằm trong `policy.yaml` (được ghim), không nằm trong `vault.json`: mọi chương trình nhận secret hoặc được broker chạy đều phải đến từ cấu hình đã ghim.
- Mặc định: secret có `env=prod` hoặc tên có đoạn `prod`/`prd` ở bất kỳ vị trí nào → `deny`, trừ khi policy ghi rõ grant cho đúng tên đó với `approval: user-presence`.
- Allowlist: mục `sql` là tên trần; broker phân giải **một lần** bằng `exec.LookPath` với PATH của chính broker thành đường dẫn tuyệt đối (EvalSymlinks) và chạy đúng đường dẫn đó. `argv[0]` của request phải là tên trần đó (không phân biệt hoa/thường, `.exe` tùy chọn trên Windows) hoặc đúng đường dẫn đã phân giải; có dấu phân cách thư mục khác → từ chối. Tham số khớp mẫu glob sau khi `Abs/Clean/EvalSymlinks`, `*` không vượt dấu phân cách, `**` thì có, cấm `..`; có chế độ khớp đúng (không cho thêm tham số). Luôn chặn shell (`sh bash zsh fish cmd powershell pwsh busybox wsl nu env xargs`…) theo đích đã phân giải. Trình thông dịch (`python py pyw node perl ruby php deno`…): `argv[1]` phải là đường dẫn script khớp mẫu, không cho tùy chọn nào đứng trước. `sql`, `sqlplus`, `java`, `make`, `git`, `ssh`, `find`, `go`, `npx`, `npm`, `uv`, `dotnet` là "script host": bắt buộc có mẫu tham số. SQLcl/sqlplus luôn được broker thêm chế độ hạn chế `-R` (mức đo thực tế ghi ở `docs/DESIGN-notes-sqlcl.md`).
- Shell script chỉ được chạy khi policy ghim đúng file: `bash sh zsh dash ksh powershell pwsh` với mẫu tham số đầu `path:<tuyệt đối, không glob>`; request phải là shell + đúng script đó (không tùy chọn, script là file thường), broker chạy `--noprofile --norc`/`-NoProfile -ExecutionPolicy Bypass -File` và xóa `BASH_ENV`/`ENV`. `cmd fish csh tcsh busybox ash wsl nu env xargs nohup start` luôn bị chặn.
- Tên biến môi trường (`env_name`, `--into`) phải khớp `^[A-Za-z_][A-Za-z0-9_]*$` và không thuộc nhóm biến nạp mã (`PATH`, `LD_*`, `DYLD_*`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `NODE_OPTIONS`, `PYTHON*`, `PERL5*`, `RUBY*`, `SQLPATH`, `TNS_ADMIN`, `CLASSPATH`, `BASH_ENV`, `PSModulePath`, `COMSPEC`).
- `--as` không được đổi `kind` của secret `oracle-wallet`; `resolve` (ghi giá trị vào file) chỉ dùng được với secret mà policy cho phép kind `template`.
- Ghi đè secret đã có, `import`, `resolve-conflict` đều cần duyệt người.
- **Phiên làm việc**: Hello lúc `kg broker` start (hoặc `kg session start`) mở phiên; `kg session end`/`kg lock` đóng. Trong phiên mọi grant có policy `user-presence`/`device` được cấp **không hỏi**, kể cả secret PROD có grant đúng tên (lựa chọn tường minh của người dùng); `approval: deny`, PROD mặc định từ chối, pin/allowlist/kind vẫn áp. Audit ghi `approval=session` + mã phiên. Phiên không hết hạn và không bị tắt bởi khóa màn hình (vault key nằm trong RAM suốt phiên). Luôn hỏi dù có phiên: `policy apply`, `reveal`, `delete`, ghi đè secret, `import`, `compare`, `resolve-conflict`, thao tác owner, thu hồi thiết bị duyệt (`revoke-approver`, Hello tại máy, không qua điện thoại). Đóng phiên xóa grant của phiên; grant bền còn nguyên.
- **Ghim hash script**: token `sha256:<hex>` đặt ngay sau mẫu `path:` trỏ đúng một file (không glob), hoặc ngay sau đường dẫn chương trình tuyệt đối, ghim nội dung; broker băm file (file thường, không symlink, đọc một lần, tối đa 16 MiB) lúc kiểm và từ chối nếu lệch (báo hash hiện tại, không báo nội dung). `approval: none` chỉ hợp lệ khi mọi `allow_commands` của grant đều ghim hash như vậy. `kg hash <file>` in hash.
- **Argv là đường dẫn đã chuẩn hóa, ghim khóa lúc chạy (rà soát 12/11/2026, A4)**: với mọi tham số khớp mẫu `path:`/`@path:` (và script của shell đã ghim), `Match.Argv` mang đúng giá trị `Abs/Clean/EvalSymlinks` đã đem đi so khớp (giữ tiền tố `@`), không phải chuỗi thô của request; đổi symlink sau khi kiểm không đổi file được chạy. Với mọi file có `sha256:` (chương trình, tham số, script shell), `Match.LockPins()` được `cmdRun` gọi ngay trước `env.Run` (đóng sau khi tiến trình con thoát): mở file, băm lại **từ chính handle đó**, giữ handle tới `Close`. Windows: `CreateFile(GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT)` (không chia sẻ WRITE/DELETE), từ chối reparse point/thư mục, so `GetFinalPathNameByHandle` với đường dẫn chuẩn hóa; trong lúc giữ handle, ghi/nối/xóa/đổi tên đè/đổi tên đi và đổi tên thư mục cha đều thất bại, còn `python script.py` hay PowerShell đọc file vẫn chạy (đã đo trên Windows 11). Unix: `O_RDONLY|O_NOFOLLOW`, băm, giữ handle, **không có khóa bắt buộc**: còn cửa sổ TOCTOU nhỏ giữa lúc băm lại và lúc tiến trình con mở file (rủi ro còn lại, chấp nhận). Khóa thất bại hoặc hash lệch → từ chối với mã `blocked`, audit `deny` (`approval=pin-lock`). Hash chỉ ghim nội dung một file: module script nhập thêm (`_kgenv.py`, `site-packages`) không được ghim.
- **Thư mục chạy nằm trong grant (A2)**: `Dir` của `kg run`/`grant` (rỗng = thư mục hiện hành của broker) được chuẩn hóa `Abs` + `EvalSymlinks` rồi đưa vào `grantKey`, `grants.json` (có trong MAC; mục không có `dir` từ bản cũ bị bỏ khi nạp, tức hỏi duyệt lại một lần), `GrantView`/`kg grants` (cột THƯ MỤC), và dòng lệnh hiển thị khi duyệt: `<argv>  (thư mục: <dir>)` (phần thư mục được giữ chỗ riêng để argv dài không đẩy nó ra khỏi 300 ký tự), nên nằm trong `Pending.Digest` và màn hình điện thoại; tiến trình con chạy đúng thư mục đã chuẩn hóa đó. Audit `grant`/`run-start`/`run` có trường `dir`. Môi trường tiến trình con luôn có `NoDefaultCurrentDirectoryInExePath=1` (CreateProcess của con không tìm chương trình trong thư mục hiện hành trước). Không có khóa `dir:` trong policy, không chèn `git -c`.
- **Cảnh báo script không ghim (A1)**: `kg policy apply` thêm `CẢNH BÁO … script không ghim nội dung (sha256): ai sửa được file thì chạy mã tùy ý với secret` cho mỗi mục `allow_commands` có chương trình là trình thông dịch hoặc shell ghim được, tham số đầu là `path:` và không có `sha256:` (policy vẫn nạp bình thường). `kg policy pin [--dry-run] <policy.yaml>` chèn/cập nhật `sha256:<hex>` (`allowlist.FileHash`) ngay sau mỗi token `path:` không glob của các mục đó, giữ nguyên mọi byte khác của file; `--dry-run` chỉ in diff. Lệnh chỉ sửa file, không áp policy: người dùng tự chạy `kg policy apply` (Windows Hello).
- Grant: duyệt một lần, khóa theo (secret, mẫu lệnh, đường dẫn chương trình đã phân giải, **thư mục chạy đã chuẩn hóa**). Grant sau một duyệt tường minh (Hello, chữ ký dán, điện thoại) là **bền**: ghi `state/grants.json` (JSON + MAC bằng khóa local-mac của thiết bị, gắn vault và thiết bị; sai MAC/JSON hỏng = bỏ hết), không hết hạn trừ khi policy ghi `ttl:`, sống qua khóa/restart/hết phiên tới khi `kg grants revoke`. Grant trong phiên (`approval=session`) và `approval: none` chỉ ở RAM. Grant bền chỉ còn hiệu lực khi policy hiện tại vẫn yêu cầu đúng kiểu duyệt đã cấp. Khôi phục bản `grants.json` cũ hợp lệ không bị phát hiện (cùng giới hạn như `policy.pin`). Hộp thoại duyệt hiện argv dạng mảng có ngoặc, bỏ ký tự điều khiển/ANSI, cắt ở 300 ký tự. Khi bật `--idle`, bộ đếm tự khóa chỉ reset bởi thao tác có người duyệt hoặc lần chạy đã được grant, không bởi `list`/`status`.
- Duyệt `user-presence`: Windows: `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` (đường dẫn tuyệt đối, `PSModulePath` chỉ thư mục hệ thống) chạy script nhúng bằng `-EncodedCommand`, gọi `UserConsentVerifier.RequestVerificationAsync(message)`; macOS: `/usr/bin/swift` inline gọi `LAContext.evaluatePolicy` (chưa kiểm được trên máy Mac); Linux: không có → dùng `device`.
- Duyệt `device`: broker in trong TTY của chính nó một challenge (`kg/v1/approval` + vault + nonce + secret + lệnh + hạn); người dùng chạy `kg approve <challenge>` trên máy khác (máy đó tự đòi duyệt người), được chuỗi chữ ký, dán vào TTY broker. Agent không gõ được vào TTY broker; chữ ký kiểm bằng khóa Ed25519 của một thiết bị thành viên khác máy đang chạy broker.
- **Duyệt từ điện thoại (thiết bị `approver`)**. `members.AddBody.Role = "approver"`: thiết bị chỉ có khóa Ed25519/X25519 để ký và nhận thông điệp, **không nhận vault key** (không wrap, không epoch, không ghi record; thu hồi đi `revoke` + epoch như thiết bị khác). Mọi nơi dựng người nhận khóa dùng `KeyHolders()`, chữ ký dán (`approval: device`) chỉ chấp nhận khóa của key holder. Thông điệp điện thoại ↔ broker là envelope AES-256-GCM (`internal/remote`): khóa HKDF từ X25519 ephemeral, ký Ed25519 của người gửi trên toàn bộ trường, `Open` chỉ nhận người gửi là **approver đang active**, bỏ thư cũ hơn `MaxMsgAge`, thư có thời gian trước lúc broker start, thư tương lai, id đã thấy (24 giờ), lệnh có `boot` khác lần chạy hiện tại (trừ `refresh`). Broker công bố `View` (trạng thái, tên secret, grant, audit 50 dòng, yêu cầu chờ, kết quả lệnh; **không** giá trị secret, không argv) niêm phong riêng cho từng approver qua relay (`PUT view`); điện thoại trả `decision` gắn với `Pending.Digest()` (op, secret, lệnh, detail, bind, hạn) và `command`.
- **Engine duyệt** (`humanApprove`): một yêu cầu = (op, secrets, command, bind). Kênh tại máy (Hello, hoặc chữ ký dán cho `approval: device` khi chưa có điện thoại) và kênh điện thoại đua nhau; màn hình khóa hoặc `RemoteDelay` (15 giây) trôi qua thì yêu cầu được công bố. Quyết định đến khi người gọi đã rời đi (`ApprovalWait` 270 giây, client nhận `pending`) được giữ `PreapprovalTTL` (10 phút) cho đúng yêu cầu đó; `bind` là bản băm dữ liệu sẽ áp dụng (nội dung file `set --from-file`, các cặp tên/giá trị của `import`/`compare`, hash `policy.yaml`) nên nội dung đổi thì không khớp. `reveal`, ghi đè, `same`, `cp` và `detail` > 32 KiB luôn chỉ làm tại máy. Danh sách approver giữ ở RAM từ lần mở khóa gần nhất; trước lần mở khóa đầu sau khi start chỉ dùng `members.kgl` khi `state/members.mac` (MAC khóa local-mac trên vault, genesis hash, số sự kiện, head hash; ghi mỗi lần mở khóa/làm mới) hợp lệ và file không ngắn hơn vị trí đã MAC (đúng head tại số sự kiện đó): cắt đuôi `members.kgl` để hồi sinh thiết bị đã thu hồi không có kênh điện thoại. Thư điện thoại chống phát lại theo id **đã ký** trong envelope (id đường dẫn relay phải trùng) và theo `cid` của lệnh; quyết định từ xa bắt buộc có digest `sha256:<hex64>` đúng của yêu cầu.
- **Ranh giới tin cậy đã chấp nhận (11/11/2026)**: mã PWA do Worker Cloudflare của chủ vault phục vụ và điện thoại được duyệt **mọi** loại yêu cầu, kể cả `policy apply`, nên tài khoản Cloudflare trở thành một phần gốc tin cậy cho quyền duyệt (khác mục 8: relay vẫn không đọc được giá trị đã lưu nhưng không còn chỉ là kênh không tin cậy). Mất tài khoản Cloudflare cộng một agent bị dẫn dắt trên laptop có thể dẫn tới lộ secret. Vault key và giá trị đã lưu không nằm trên điện thoại hay Worker. Thu hẹp sau này: đặt `localOnly` cho op `policy` (một dòng trong bảng op của `approval.go`).

## 10. Chạy lệnh và che đầu ra (FR-03, FR-05)

- `kg run --secret A [--secret B] [--as env|file|wallet] -- cmd args…`: broker kiểm grant, ghi audit "bắt đầu" (ghi lỗi → không chạy), giải mã, dựng môi trường tạm, chạy tiến trình con (broker là cha), trả stdout/stderr đã che + mã thoát qua socket (stream). Vật liệu tạm (file, wallet) nằm dưới `KG_HOME/run/` (0700), ghi đè nội dung trước khi xóa, dọn sót ở lần broker khởi động. Diệt cả cây tiến trình (Windows Job Object `KILL_ON_JOB_CLOSE`; unix process group), `WaitDelay`, thời gian chạy tối đa mặc định 30 phút (`max_runtime` theo grant).
- `env`: đặt `env_name`. `file`: ghi file tạm quyền 600, đặt biến `KG_FILE_<NAME_UPPER>` (hoặc `env_name`) = đường dẫn. `oracle-wallet`: thư mục tạm có wallet tạo bằng `OracleSecretStoreTextUI` (oraclepki.jar của SQLcl, JDK ≥ 11; mật khẩu wallet ngẫu nhiên, mọi mật khẩu đưa qua **stdin**, không qua argv; đầu ra của công cụ cũng được che), `tnsnames.ora` chép từ `oracle.tns_admin` đã ghim, `sqlnet.ora` có `WALLET_LOCATION` + `SQLNET.WALLET_OVERRIDE=TRUE`; đặt `TNS_ADMIN` cho tiến trình con.
- Redactor: với mỗi giá trị đã cấp trong phiên (độ dài ≥ 4; thêm biến thể bỏ khoảng trắng/xuống dòng cuối và CRLF), che: nguyên văn, base64 std/url có và không padding ở cả 3 độ lệch (bỏ ký tự biên), URL-encoded (không phân biệt hoa/thường `%xx`) → `[kg:<tên>]`. stdout và stderr đi qua một luồng che có thứ tự. Ngoài phạm vi (rủi ro còn lại): hex, đảo chuỗi, JSON-escape, UTF-16, nén, giá trị < 4 ký tự.
- `kg resolve <file> [--into ENV] -- cmd…`: thay `${secret:NAME}` trong file, ghi file tạm, đặt biến `KG_RESOLVED` (hoặc `--into`) = đường dẫn, chạy lệnh qua cùng đường grant/che.

## 11. Hook (FR-04)

- `kg hook check`: đọc JSON PreToolUse (Claude Code: `{tool_name, tool_input}`; omp: `{toolName, input}`) từ stdin. Chặn → in lý do ra stderr, thoát 2. Cho qua → thoát 0.
- Chặn: đọc/grep/cat các file `.env`, `.env.*`, `*.sso`, `*.p12`, `cwallet*`, thư mục `KG_HOME`; lệnh `env`, `printenv`, `set` (đứng một mình), `Get-ChildItem Env:`, `gci env:`, `ls env:`, `$env:` liệt kê, `[Environment]::GetEnvironmentVariables`; `kg reveal`; chuỗi giống mật khẩu trong lệnh (`user/pass@`, `-p<pass>`, `--password=`, `Authorization: Bearer <token dài>`, `PASSWORD=…`).
- `integrations/claude-code/settings.snippet.json` (PreToolUse matcher `Bash|Read|Grep|Glob|Edit|Write`) và `integrations/omp/keygate-hook.ts` (`pi.on("tool_call")` gọi `kg hook check`, trả `{block:true, reason}`).

## 12. MCP (FR-08)

`kg mcp`: JSON-RPC 2.0 qua stdio, MCP `2025-06-18`: `initialize`, `tools/list`, `tools/call`. Tool: `list_secrets` (tên, env, kind, lần dùng cuối, trạng thái xung đột), `request_grant {secret, command}`, `run_with_secret {secrets[], argv[]}` (trả stdout đã che + exit code). Không có tool trả giá trị.

## 13. Audit (FR-10)

Mỗi dòng: `{"n","time","prev","event":"grant|run-start|run|reveal|deny|set|import|policy","secret","env","argv","dir","agent","peer","approval","exit","mac"}`; `prev` = sha256 dòng trước; `mac` = HMAC-SHA256(local-mac key, dòng không có mac). Đầu chuỗi (hash + số dòng) được neo trong `state/` có MAC, nên cắt đuôi hay xóa file đều bị `kg audit verify` phát hiện. `kg audit show --since 7d` kiểm MAC trước khi hiện, để trả lời "tuần trước agent dùng secret nào, vào đâu". `agent` là nhãn tự khai; `peer` là PID/đường dẫn tiến trình gọi khi hệ điều hành cho biết.

## 14. Thiết bị và khôi phục (FR-13, FR-14)

- `kg init --label laptop`: sinh vault, khóa thiết bị, hỏi mật khẩu chủ (2 lần, ẩn, tối thiểu 12 ký tự), sinh khóa giấy, in khóa giấy một lần trong TTY, ghi genesis + add + epoch 1.
- `kg device request --label mac` (máy mới): sinh khóa thiết bị, in mã đăng ký (base32 của `{dev,label,ed_pub,x_pub}`) + 6 từ xác nhận.
  - Khác PRD: PRD ghi mã QR. Không làm QR vì cần thư viện QR ngoài danh sách dependency cho phép; mã văn bản + 6 từ giữ nguyên tính năng xác nhận.
- `kg device add <mã>` (máy cũ): hiện 6 từ để so, đòi mật khẩu chủ + khóa giấy, ghi `add` + bọc vault key epoch hiện tại cho thiết bị mới (sự kiện `epoch` cùng số epoch, thêm wrap), in vault ID + ghim genesis để nhập ở máy mới (`kg join --vault … --pin …`).
- Ghép điện thoại duyệt (sửa 12/11/2026, R1+R2+R3): laptop (`kg device pair` hoặc khay "Ghép điện thoại…") sinh `code16` (80 bit) và `nonce` (16 byte ngẫu nhiên, base64url không đệm, không gửi lên relay), `PUT pair-open/{code16}` (ký), rồi hiện liên kết/QR `<relay>/app/#v=<vault>&p=<ghim genesis>&c=<code16>&n=<nonce>` và đứng chờ (poll `GET pair/{code16}` mỗi 2 giây, tối đa 10 phút). Điện thoại tạo khóa, `PUT pair/{code16}` với mã đăng ký, hiện 6 từ `PairWords(mã đăng ký, nonce)` = `Words(sha256("kg/v1/pair-words\x00" + lp(nonce) + lp(mã đăng ký chuẩn hóa)))`. Laptop nhận mã đăng ký, **bắt buộc `role = approver`** (mã thiết bị đầy đủ bị từ chối, chỉ đi qua `kg device add <mã>`), hiện cùng 6 từ để bạn so với màn hình điện thoại rồi mới ghi `add`. Mã 8 ký tự cũ, `kg device pair-url`, `kg device add --pair` đã bỏ. `kg device add <mã đăng ký>` (không qua relay, 6 từ `RequestWords`) giữ cho thiết bị đầy đủ.
  - Nonce nằm trong phần fragment nên không đi tới relay: nó chỉ chặn relay thụ động/kẻ đọc kho lưu (không thể dò mã đăng ký thay thế trùng 6 từ vì không biết nonce). PWA do chính relay phục vụ nên relay chủ động đọc được `location.hash`; điều đó nằm trong ranh giới tin cậy "PWA/Worker" đã chấp nhận ở §9. Việc so 6 từ vẫn là bước kiểm cuối: một tiến trình cùng người dùng nhìn thấy QR có thể chạy đua `PUT pair` trước điện thoại, và chỉ so 6 từ mới lộ ra điều đó.
- `kg device revoke <dev>`: đòi mật khẩu chủ + khóa giấy, ghi `revoke` + `epoch` mới, mã hóa lại mọi item, in danh sách secret mà thiết bị đó từng giải mã (từ audit ledger các máy, nếu có) để đổi ở hệ thống đích.
- `kg recover --from <dir|relay-url> --vault <id> --label <tên>`: đòi mật khẩu chủ + khóa giấy → recovery key mở vault key epoch mới nhất, owner key thêm máy này làm thiết bị mới. Genesis được ràng buộc qua việc so `owner_pub`/`recovery_pub` dẫn xuất với genesis.

## 15. Lệnh CLI

`kg init | set | import | list | run | resolve | grant | reveal | conflicts | resolve-conflict | sync | fingerprint | device request|add|revoke | recover | approve | broker | policy apply|pin | audit verify|show | hook check | mcp | lock | status`. Không có `kg get`.

## 16. Kiểm chứng

- `go test ./...`: test vector (`testdata/vectors.json`, khóa/nonce cố định), fuzz bộ phân tích bản ghi, bộ tấn công 5/5, redactor, allowlist, hook, policy parser.
- `relay/`: `wrangler dev` + `kg sync` giữa hai `KG_HOME`.
- Smoke thật (luật repo): người dùng tự `kg set` mật khẩu schema TEST trong terminal, agent chạy `kg run … -- sql /@<alias>`, duyệt Windows Hello, kiểm transcript không có giá trị.
