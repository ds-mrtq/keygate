# API của lõi (kcrypto, record, members, checkpoint, devkey, recovery, store, syncer, fsx)

Module `keygate`. Mọi lỗi kiểm tra là lỗi có kiểu, so bằng `errors.Is`. Không hàm nào in giá trị secret.

## Lỗi có kiểu (khai báo trong `store`, `syncer` xuất lại 6 lỗi đầu)

| Lỗi | Nghĩa |
|---|---|
| `store.ErrBadSignature` (= `kcrypto.ErrBadSignature`) | bản ghi/checkpoint bị sửa hoặc hỏng cấu trúc |
| `store.ErrUnknownDevice` | `dev` không có trong members, thiết bị bị thu hồi ghi quá `last_seq`, sự kiện members không do owner ký |
| `store.ErrBrokenChain` | `prev` sai, seq nhảy, fork trong log một thiết bị hoặc chuỗi members |
| `store.ErrRollback` | seq cao nhất của kênh < high-water trong `state/local.json` (cũng bắt log cục bộ bị cắt ngắn khi `Open`) |
| `store.ErrHidden` | checkpoint hợp lệ cho biết có bản ghi/sự kiện mà kênh không đưa |
| `store.ErrFork` | hai kênh cho trạng thái khác nhau (`syncer.VerifyVia`) |
| `store.ErrConflict` | item có ≥ 2 head |
| `store.ErrPin` | genesis của kênh không khớp mã ghim (`GenesisPin`) |
| `store.ErrForkChannel` (`syncer.ErrForkChannel`) | kênh đã có dòng khác ở vị trí ta đẩy (`ErrExists` nhưng nội dung khác) |
| `store.ErrNotFound`, `ErrDeleted`, `ErrNoKey`, `ErrLocalState`, `ErrWrongKeys`, `ErrNotOwner`, `ErrNotMember`, `ErrExists` | tra cứu, tombstone, thiếu khóa epoch, MAC state hỏng/thiếu, sai mật khẩu/khóa giấy, sai owner key, thiết bị không còn là thành viên, KG_HOME đã có vault |

## kcrypto

- `Label*` (`LabelRecord`, `LabelMember`, `LabelCheckpoint`, `LabelRelayReq`, `LabelApproval`, `LabelItemKey`, `LabelWrap`, `LabelRecovery`, `LabelLocalMac`): nhãn domain, kết thúc `\x00`.
- `NewEnc(label) *Enc`; `(*Enc).U64(n)`, `.LP([]byte)`, `.LPS(string)`, `.LPOpt(*string)`, `.Bytes()`: dựng chuỗi canonical length-prefixed.
- `B64(b) string`, `UnB64(s) ([]byte, error)`: base64 std, giải mã nghiêm ngặt.
- `SHA256Ref(parts...) string` ("sha256:hex"), `IsHashRef(s) bool`.
- `NewVaultID/NewDeviceID/NewItemID() string`, `ValidVaultID/ValidDeviceID/ValidItemID(s) bool`, `NewID`, `ValidID`.
- `RandBytes(n)`, `NewVaultKey() []byte`, `HKDF(ikm, info, n) []byte`, `MAC(key, data) []byte` (HMAC-SHA256).
- `Argon2Params{T,M,P}`, `DefaultArgon2` (3, 64 MiB, 4), `(Argon2Params).Validate()`, `Argon2ID(pwd, salt, params) []byte`.
- `GenerateSignKey() (pub, priv)` Ed25519; `GenerateX25519() (priv, pub [32]byte)`; `X25519Public(priv)`.
- `Seal(key, nonce, pt, aad)`, `Open(key, nonce, ct, aad)` (XChaCha20-Poly1305; lỗi giải mã = `ErrDecrypt`).
- `ItemKey(vaultKey, vault, epoch, item) []byte`.
- `Wrap{Rcpt,Eph,Nonce,CT}`, `(Wrap).Validate()`, `WrapKey(vault, epoch, rcptID, rcptPub, vaultKey)`, `WrapKeyWith(ephPriv, nonce, ...)` (tất định, cho vector), `UnwrapKey(vault, epoch, wrap, rcptPriv)`.

## record (mục 4.1)

- `Record` (trường JSON đúng DESIGN), `Plain{Name,Value,Desc,Tags,Env,Kind,EnvName,TNS,User,FileExt}`.
- `Parse(line) (*Record, error)`: giải mã + kiểm cấu trúc nghiêm ngặt (không kiểm chữ ký); lỗi bọc `ErrMalformed`.
- `(*Record).Canonical()`, `.Sign(priv)`, `.Verify(pub)` (lỗi `kcrypto.ErrBadSignature`), `.Hash()`, `.AAD()`, `.Marshal()`.
- `(*Record).Encrypt(vaultKey, Plain)`, `.EncryptWithNonce(vaultKey, nonce, Plain)`, `.Decrypt(vaultKey) (Plain, error)`: đặt Vault/Item/Parent/Epoch/Dev/Seq/Op trước khi Encrypt; tombstone chỉ giữ `name`.
- `StrPtr(s) *string`, hằng `OpPut`, `OpTombstone`, `CurrentVer`.

## members (mục 4.2)

- `Event{V,Vault,N,Prev,Type,Body,Sig}`, `GenesisBody`, `AddBody`, `RevokeBody{Dev,Reason,LastSeq}`, `EpochBody{Epoch,Wraps}`.
- `New(vault, n, prev *Event, type, body any, ownerPriv) (*Event, error)`; `Parse(line)`; `(*Event).Canonical/Sign/Verify(ownerPub)/Hash/Marshal/DecodeBody`.
- `NewEpochBody(vault, epoch, vaultKey, []Recipient{ID, XPub})`; `RecoveryRcpt = "recovery"`.
- `State` (Vault, OwnerPub, RecoveryPub, ArgonSalt/Params, Devices, Epoch, Wraps, Count, Head, PendingEpoch); `Device{ID,Label,EdPub,XPub,AddedN,Revoked,LastSeq}`.
- `NewState()`, `Replay(lines) (*State, error)`, `(*State).Apply(ev)`, `.Clone()`, `.Active()`, `.UnwrapKey(epoch, rcptID, xPriv)`.
- `RevokeBody{Dev,Reason,LastSeq,LastHash}`: `last_hash` = record_hash của bản ghi thiết bị bị thu hồi tại `last_seq` ("" iff `last_seq`=0); bản ghi tại `last_seq` phải khớp hash này (`ErrBrokenChain`), bản ghi seq > `last_seq` bị BỎ (không lỗi, không lưu).
- `State.GenesisHash`.
- Parse nghiêm: `json.Marshal(parsed)` phải bằng đúng dòng nhập (record, member, checkpoint), base64 không chứa CR/LF.
- Lỗi: `ErrMalformed`, `ErrBadOwnerSig`, `ErrChain`, `ErrInvalid`, `ErrNoWrap`.
- Luật replay: revoke phải theo ngay bằng epoch+1 gói khóa cho mọi thiết bị còn hoạt động + `recovery`; add đi kèm epoch cùng số chỉ thêm wrap cho thiết bị mới.

## checkpoint (mục 4.3)

- `Checkpoint{V,Vault,Dev,Time,MembersN,Seen,Sig}`; `Parse(b)`, `.Canonical()`, `.Sign(priv)`, `.Verify(pub)`, `.Marshal()`, `.Total()`.

## devkey (mục 3)

- `Store{Name, Save(dev, secret), Load(dev)}`; `ErrNotFound`; `EnvBackend = "KG_DEVKEY_BACKEND"`.
- `Open(home, Options{Password, Argon}) (Store, error)`: Windows DPAPI (`device.key.dpapi`, entropy = dev id), macOS `security -i` (secret qua stdin), còn lại file `device.key.enc` 0600 Argon2id. `KG_DEVKEY_BACKEND=plain` chọn backend `plain` (cảnh báo ra stderr, chỉ cho test).
- `PlainAllowed` (const): `KG_DEVKEY_BACKEND=plain` chỉ được chấp nhận khi build với `-tags kgtest`; build thường trả lỗi.
- `NewPlain(home)`, `NewFile(home, Options)`; `PasswordFunc func(confirm bool) (string, error)`.

## recovery (mục 3)

- `Keys{OwnerPriv, OwnerPub, RecoveryPriv, RecoveryPub}`.
- `Derive(vault, pwd, salt, params, paperKey32) (*Keys, error)`.
- `NewSetup(vault, pwd, params) (*Setup{Keys, Salt, Params, PaperKey}, error)`: sinh salt + khóa giấy.
- `EncodePaperKey(raw32) string` (base32, nhóm 4 ký tự nối `-`, nhóm cuối là CRC32 4 ký tự); `ParsePaperKey(s) ([]byte, error)` (không phân biệt hoa/thường, bỏ khoảng trắng và `-`, lỗi `ErrPaperKey`).

## store (mục 4-6, 14)

- Khởi tạo/mở: `Init(home, vault, id, keys, salt, params, created) (*Store, error)`; `Open(home, id)` (kiểm lại toàn bộ chữ ký, chuỗi, high-water; cắt dòng cuối bị đứt ghi kèm cảnh báo; giữ khóa `KG_HOME/lock` cho tới `Close()`, khóa của tiến trình đã chết được thu hồi, `fsx.ErrLocked` nếu tiến trình khác đang giữ); `(*Store).Close()`; `Join(home, id, fullSnapshot, pin)` (bắt buộc pin, sai/trống -> `ErrPin`; vault ID không lấy từ kênh: pin gắn với vault ID và genesis hash); `Recover(home, id, *recovery.Keys, fullSnapshot, pin)` (pin tùy chọn vì khóa dẫn xuất đã buộc owner/recovery pub; khóa sai -> `ErrWrongKeys`, không để lại file); `DefaultHome()`.
- Ghim genesis: `GenesisPinOf(vault, genesisHash)`, `(*Store).GenesisPin()` = base32 hoa, nhóm 4 ký tự nối `-`, của 15 byte đầu sha256(genesis hash thô || vault id) (24 ký tự, 29 với dấu `-`).
- Danh tính: `Identity{Dev,Label,EdPriv,EdPub,XPriv,XPub}`, `NewIdentity(label)`, `(*Identity).Public() members.AddBody`, `.Secret()`, `.DeviceID()`, `.Sign(msg)` (là `transport.Signer`), `IdentityFromSecret`, `SaveIdentity(home, id, devkey.Store)`, `LoadIdentity(home, devkey.Store)`.
- Cấu hình: `Vault()`, `Config() VaultConfig`, `SaveConfig(VaultConfig)` (vault.json: `relay_url`, `git_dir`, `sync_dir`, `oracle{pki_jar,java,tns_admin}`).
- Item: `Put(item|"" , record.Plain) (*record.Record, error)`, `Delete(item)`, `Get(item) (Plain, *Record, error)` (`ErrConflict`/`ErrDeleted`/`ErrNotFound`/`ErrNoKey`), `List() []ItemInfo`, `FindByName(name) (ItemInfo, error)`, `Conflicts() []ItemInfo`, `ResolveConflict(item, keepHashOrDev)`, `ReencryptLive() (int, error)`. `ItemInfo{Item,Name,Kind,Env,Deleted,Conflict,Undecryptable,Heads[]Head{Hash,Dev,Seq,Op,Epoch}}` không chứa giá trị.
- Thao tác owner (cần `ed25519.PrivateKey` từ `recovery.Derive`, sai -> `ErrNotOwner`): `AddDevice(owner, members.AddBody)` (add + epoch cùng số có wrap cho máy mới), `RevokeDevice(owner, dev, reason) (reencrypted int, err)` (revoke với `last_seq` từ dữ liệu cục bộ + epoch+1 + mã hóa lại mọi item sống).
- Đồng bộ (con trỏ THEO KÊNH, `ch` = `transport.Name()`; `""` = con trỏ toàn cục): `Since(ch) transport.Since` (cố ý hỏi lại dòng cuối đã xác nhận, `hw-1`; kênh chưa từng sync có con trỏ rỗng nên kéo đầy đủ và được đẩy đầy đủ, không báo `ErrRollback`), `IngestFrom(ch, Snapshot) (IngestResult, error)` (kiểm toàn bộ, lỗi thì không ghi gì; bản ghi của thiết bị bị thu hồi vượt `last_seq` bị bỏ; checkpoint của thiết bị bị thu hồi bị bỏ qua; `parent`/`merge` trỏ sang item khác -> `record.ErrMalformed`), `PendingMembers(ch)`, `PendingOwnLines(ch)`, `MarkPushed(ch, ownSeq, membersN)`, `WriteCheckpoint(now) ([]byte, error)`.
- Trạng thái: `Members() *members.State`, `Epoch()`, `Fingerprint()` (6 từ), `Words(sum []byte) string` (6 từ từ sum[0..5], cho mã xác nhận thiết bị), `ViewFingerprint(snapshot)`, `LocalMacKey() []byte` (HKDF từ seed Ed25519 thiết bị, nhãn `kg/v1/local-mac`; dùng cho audit/policy pin).
- `state/local.json` (toàn cục) và `state/channels/<kênh>.json` (theo kênh): high-water từng thiết bị + số sự kiện members, HMAC-SHA256 (so bằng `hmac.Equal`, MAC bao gồm loại file, vault id, device id, tên kênh); sửa/thiếu `local.json` -> `ErrLocalState`. High-water của chính thiết bị chỉ tăng khi đã đẩy lên kênh (`MarkPushed`).

## syncer (mục 7)

- `Syncer{Store, T transport.Transport, Now}`; `(*Syncer).Sync(ctx) (Result, error)`: pull(`Since(T.Name())`) -> `IngestFrom` -> đẩy members/log mới (khi `transport.ErrExists`, kéo lại toàn bộ và so từng byte; khác -> `ErrForkChannel`) -> ghi + đẩy checkpoint -> `MarkPushed`.
- `VerifyVia(ctx, st, primary, secondary Transport) (fingerprint, error)`: kéo toàn bộ từ cả hai kênh, kiểm từ đầu, so fingerprint; khác nhau -> `ErrFork`.
- Xuất lại: `ErrBadSignature`, `ErrUnknownDevice`, `ErrBrokenChain`, `ErrRollback`, `ErrHidden`, `ErrFork`, `ErrForkChannel`.
- Lưu ý cho transport: `Pull` phải trả mọi dòng có seq > `Since.Logs[dev]` và mọi sự kiện có n >= `Since.Members`; thiết bị không có trong `Since.Logs` thì trả từ đầu. Race hiếm (sự kiện `add` đẩy sau lúc kéo members) gây `ErrUnknownDevice` tạm thời, chạy lại sync là hết.

## fsx

- `WriteAtomic(path, data)` (temp + rename, 0600), `AppendLines(path, lines...)` (fsync), `ReadLines(path)`, `ReadLinesRepair(path)` (cắt dòng cuối không có `\n`), `Lock(path) (unlock, error)` (O_EXCL + pid, thu hồi khóa mồ côi, tái nhập trong cùng tiến trình), `ErrLocked`.

## Kiểm chứng

- `testdata/vectors.json`: sinh lại bằng `go test ./internal/vectors -update`; test thường so khớp byte và dựng lại chuỗi canonical thủ công theo DESIGN.
- `FuzzParseRecord` (`internal/record`): `go test ./internal/record -fuzz FuzzParseRecord`.
- `TestAttacks` (`internal/syncer`): modify, insert-device, delete-middle, rollback, hide.

## Chạy test

`go test -tags kgtest ./...` (backend `plain` của devkey chỉ bật với tag `kgtest`; không có tag thì test dùng `plain` tự skip hoặc fail trong broker/cmd).
