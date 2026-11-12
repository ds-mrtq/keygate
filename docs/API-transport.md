# API: internal/transport/{dir,git,relay}

Giao diện cố định: `internal/transport/transport.go` (`Transport`, `Since`, `Snapshot`, `Signer`, `ErrExists`). Transport chỉ chuyển dòng thô, không parse/verify.

Quy ước chung
- `Since.Members` = số sự kiện members đã có; `Pull` trả các sự kiện từ chỉ số đó. Sự kiện `n` (0-based) ứng với `PushMember(n, …)`.
- `Since.Logs[dev]` = seq cao nhất đã có; `Pull` trả `Logs[dev]` = các dòng seq+1… theo thứ tự. seq của dòng thứ i trong file = i (1-based), tức log liên tục không nhảy.
- `PushLog/PushMember` trả `transport.ErrExists` nếu seq/n đã có.
- Dòng là JSON thô, không chứa `\n`. `Checkpoints[dev]` = JSON mới nhất.

## `dir`
```go
d, err := dir.New(root, selfDeviceID)   // *dir.Dir
d.Name() == "dir"; d.Root()
```
Layout: `members.kgl`, `log/<dev>.kgl`, `checkpoints/<dev>.json`. Chỉ ghi file của `selfDeviceID`. `PushLog` seq phải đúng bằng số dòng+1 (nhỏ hơn/bằng -> ErrExists, lớn hơn -> lỗi gap); `PushMember` tương tự. Pull trả đúng các dòng đang nằm trong file (caller so sánh khi ErrExists).
Cứng hóa: file 0600, thư mục 0700; Lstat + từ chối symlink/file không thường (O_NOFOLLOW trên unix; Pull bỏ qua mục không thường, Push lỗi); thư mục `log`/`checkpoints` là symlink -> lỗi; đọc tối đa 64 MiB/file; append fsync; dòng cuối thiếu `\n` (ghi dở) coi như không tồn tại và bị cắt trước khi append; checkpoint ghi qua `os.CreateTemp` + fsync + rename. Thư mục thiếu = rỗng.
Thứ tự đọc của Pull (mọi transport): checkpoints -> members -> logs.

## `git`
```go
g, err := git.New(workTreePath, selfDeviceID) // thư mục phải đã là git work tree
g.SetBatch(true)   // hoãn commit/push
g.Flush(ctx)       // add -A, commit, push (thử lại một lần sau pull --rebase nếu bị từ chối)
```
Bọc `dir` trong work tree. `Pull` = `git pull --rebase origin <branch>` rồi đọc dir. Mỗi `Push*` (không batch) = pull --rebase, ghi, add, commit, push `HEAD:refs/heads/<branch>`. Không có remote `origin` hoặc remote chưa có nhánh -> bỏ qua pull/push (dùng được cục bộ). Chạy git qua `os/exec`, `GIT_TERMINAL_PROMPT=0`, user.name/email tạm `keygate`.

## `relay`
```go
c := relay.New("https://x.workers.dev", "vlt_…", signer, nil /*http.Client*/)
relay.Canonical(method, pathQuery, rfc3339Time, body) []byte // byte được ký
```
Mỗi request mang `KG-Device`=`signer.DeviceID()`, `KG-Time` (RFC3339 UTC, mili giây, **đơn điệu tăng nghiêm ngặt** — client tuần tự hóa request và tự cộng 1ms nếu cần; relay từ chối KG-Time không lớn hơn lần trước của cùng thiết bị), `KG-Sig`=base64 std `signer.Sign(Canonical(...))`. 409 -> `transport.ErrExists`; mã khác 2xx -> lỗi `relay: <op>: HTTP <code>: …`. Pull = GET checkpoints, GET members?since=N, rồi GET log?since=… lặp theo `"more":true` (2000 dòng/trang; kiểm seq liên tục). Không có WebSocket trong client Go.
Vault phải nằm trong `ALLOWED_VAULTS` của relay (nếu không: 403). Owner (`DeviceID()=="owner"`) đọc được mọi GET nên `kg recover` từ relay hoạt động; `cmd/kg` đã dùng `ownerSigner`, không cần đổi.
Relay kiểm chữ ký owner + chuỗi prev của mọi sự kiện member (sai -> 400, client Go trả lỗi HTTP 400); checkpoint lùi -> 422; seq log nhảy -> 400; vault đầy -> 507.

Lưu ý khởi tạo vault: genesis (`PushMember(0,…)`) và các sự kiện `add` đầu tiên phải ký request bằng **khóa owner** với `DeviceID()=="owner"` (Signer riêng của luồng `kg init`/`recover`); các request sau ký bằng khóa thiết bị. Chi tiết quy tắc ở `relay/README.md`.
Định dạng JSON GET: `{"logs":{dev:[{seq,line}]},"more":bool}`, `{"members":[{n,line}]}`, `{"checkpoints":{dev:body}}`.
