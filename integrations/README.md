# Tích hợp KeyGate với agent

Cần có `kg` trong `PATH`. Hook chặn agent đọc `.env`, `*.sso`, `*.p12`, `cwallet*`, thư mục `KG_HOME`, dump biến môi trường, `kg reveal` và mật khẩu gõ thẳng trong lệnh. MCP cho agent xin quyền và chạy lệnh với secret mà không bao giờ thấy giá trị.

## Claude Code

1. Hook: gộp `claude-code/settings.snippet.json` vào `~/.claude/settings.json` (hoặc `.claude/settings.json` của dự án). Nếu đã có `hooks.PreToolUse`, thêm phần tử trong snippet vào mảng đó, đừng ghi đè.
2. MCP: gộp `claude-code/mcp.snippet.json` vào `.mcp.json` của dự án (hoặc chạy `claude mcp add keygate -- kg mcp`).
3. Khởi động lại Claude Code. Thử: yêu cầu agent `cat .env`, phải bị chặn với lý do bằng tiếng Việt.

## omp

1. Hook: chép `omp/keygate-hook.ts` vào `~/.omp/agent/hooks/pre/keygate-hook.ts`.
   - Windows: `%USERPROFILE%\.omp\agent\hooks\pre\keygate-hook.ts`.
2. Hành vi: thiếu `kg` trong PATH thì chỉ cảnh báo và cho qua (fail open); mọi lỗi khác (timeout, exit lạ) thì chặn (fail closed).
3. MCP: thêm server `keygate` với lệnh `kg mcp` (stdio) vào cấu hình MCP của omp, cùng dạng với `claude-code/mcp.snippet.json`.

## Công cụ MCP

| Tool | Tham số | Kết quả |
|---|---|---|
| `list_secrets` | không | tên, env, kind, lần dùng cuối, xung đột |
| `request_grant` | `secret`, `command[]` | thông tin grant (không có giá trị) |
| `run_with_secret` | `secrets[]`, `argv[]`, `dir?` | stdout/stderr đã che + mã thoát |

Không có tool nào trả giá trị secret.

## Kiểm tra nhanh hook

```
echo '{"tool_name":"Bash","tool_input":{"command":"cat .env"}}' | kg hook check ; echo $?   # 2
echo '{"tool_name":"Bash","tool_input":{"command":"cat README.md"}}' | kg hook check ; echo $?   # 0
```
