// KeyGate PreToolUse hook for omp.
// Install: copy to ~/.omp/agent/hooks/pre/keygate-hook.ts
// Calls `kg hook check` with {"toolName","input"} on stdin; exit code 2 = block.
import { spawn } from "node:child_process";

const TIMEOUT_MS = 10_000;

type Verdict = { kind: "allow" } | { kind: "block"; reason: string } | { kind: "missing" };

function check(payload: string): Promise<Verdict> {
	return new Promise((resolve) => {
		let stderr = "";
		let settled = false;
		const done = (v: Verdict) => {
			if (!settled) {
				settled = true;
				clearTimeout(timer);
				resolve(v);
			}
		};
		const child = spawn("kg", ["hook", "check"], { stdio: ["pipe", "ignore", "pipe"], windowsHide: true });
		const timer = setTimeout(() => {
			child.kill();
			done({ kind: "block", reason: "KeyGate: hook check quá thời gian, chặn để an toàn." });
		}, TIMEOUT_MS);
		child.stderr.on("data", (d) => {
			stderr += d.toString();
		});
		child.on("error", (err: NodeJS.ErrnoException) => {
			// Binary absent: fail open (warned by caller). Any other spawn error: fail closed.
			if (err.code === "ENOENT") done({ kind: "missing" });
			else done({ kind: "block", reason: `KeyGate: không chạy được kg hook check (${err.code ?? "lỗi"}).` });
		});
		child.on("close", (code) => {
			if (code === 0) done({ kind: "allow" });
			else if (code === 2) done({ kind: "block", reason: stderr.trim() || "KeyGate: bị chặn bởi hook." });
			else done({ kind: "block", reason: `KeyGate: hook lỗi (exit ${code}). ${stderr.trim()}`.trim() });
		});
		child.stdin.on("error", () => {});
		child.stdin.end(payload);
	});
}

let warnedMissing = false;

export default function (pi: any) {
	pi.on("tool_call", async (event: { toolName: string; input: unknown }) => {
		const v = await check(JSON.stringify({ toolName: event.toolName, input: event.input }));
		if (v.kind === "block") return { block: true, reason: v.reason };
		if (v.kind === "missing" && !warnedMissing) {
			warnedMissing = true;
			console.warn("[keygate] không tìm thấy `kg` trong PATH — hook KeyGate không hoạt động.");
		}
		return undefined;
	});
}
