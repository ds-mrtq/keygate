# API: hook, mcp, importer

## `keygate/internal/hook`
- `Check(input []byte, kgHome string) (blocked bool, reason string, err error)` — nhận JSON PreToolUse (Claude Code `{tool_name,tool_input}` hoặc omp `{toolName,input}`). `err` chỉ khi JSON hỏng (caller fail closed). `reason` tiếng Việt, luôn nhắc `kg run --secret <tên> -- ...`. CLI: blocked → in reason ra stderr, exit 2.
- Trường kiểm: `file_path`, `path`, `pattern`, `glob`, `notebook_path` (luật đường dẫn) và `command` (luật lệnh). Selector omp `file:1-5` được bỏ khi so tên.

## `keygate/internal/mcp`
- `Serve(ctx, r io.Reader, w io.Writer, b api.Broker) error` — JSON-RPC 2.0 theo dòng, MCP `2025-06-18`. Trả nil khi EOF, `ctx.Err()` khi hủy. Agent label cố định `"mcp"`. Tool: `list_secrets`, `request_grant{secret,command[]}`, `run_with_secret{secrets[],argv[],dir?}`; lỗi broker → `isError:true`; tool lạ → JSON-RPC -32602. Mỗi luồng stdout/stderr giới hạn 1 MiB.
- `const ProtocolVersion`.

## `keygate/internal/importer`
- `type Entry{Key, Value string; Line int}`; `ParseDotenv(path) ([]Entry, error)` — bỏ giá trị rỗng và `${secret:...}`.
- `RewriteDotenv(path, refs map[string]string) error` — KEY → `${secret:<ref>}`, giữ nguyên dòng khác/CRLF/comment cuối dòng; ghi atomic (temp cùng thư mục + rename, giữ mode).
- `type Finding{File string; StartLine int; RuleID, Secret string}` (JSON tag gitleaks `File`,`StartLine`,`RuleID`,`Secret`); `ParseGitleaks(path)` từ chối báo cáo `--redact`.
- `RewriteFinding(f Finding, ref string) error` — thay đúng chuỗi secret tại dòng đó; lỗi không chứa giá trị.
- `SuggestName(prefix, key string) string` — `llm/` + `OPENAI_API_KEY` → `llm/openai-api-key`.

## integrations/
`claude-code/settings.snippet.json`, `claude-code/mcp.snippet.json`, `omp/keygate-hook.ts`, `README.md` (tiếng Việt).

## Giới hạn của hook
Hook chỉ là speed bump (chặn lối đi hiển nhiên, nhắc agent dùng `kg run`), không phải ranh giới bảo mật: agent cùng user OS luôn có thể tìm đường khác (binary sao chép, script tự viết, mã hóa đầu ra...). Kiểm soát thật là broker (allowlist, grant, duyệt, che đầu ra). Hook phủ thêm: glob `.e*`/`.en?`/`*.env`, nhiều path ngăn bởi `;`, `file://` trong WebFetch, grep/rg đệm quy từ khóa secret, `rg --hidden`, one-liner python/node/perl/ruby đọc env, `declare -p`, `compgen -v`, `ps e*`, `bash -c`/`cmd /c` (kiểm lại phần lệnh bên trong), `.keygate` / `KG_HOME` / `kg-file-*` / `kg-wallet-*` / `broker.sock`, `security find-generic-password`, `kg reveal` trong subshell/backtick/dấu nháy.
