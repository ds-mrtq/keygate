// Device self-check for the phone app: each WebCrypto / IndexedDB / network step the pairing
// flow depends on, with a timeout so a hang shows up as "TREO" instead of a silent stall.
// Shows no key material; safe to screenshot and send.
import * as P from "./proto.js";

const out = document.getElementById("out");
const line = (ok, name, info) => {
  const row = document.createElement("div");
  row.className = ok === true ? "ok" : ok === false ? "bad" : "info";
  row.textContent = `${ok === true ? "OK  " : ok === false ? "LỖI " : "    "}${name}${info ? ": " + info : ""}`;
  out.append(row);
};
const within = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`TREO quá ${ms / 1000} giây`)), ms))]);
async function step(name, fn, ms = 10000) {
  try {
    const info = await within(fn(), ms);
    line(true, name, info ?? "");
    return true;
  } catch (e) {
    line(false, name, e?.message ?? String(e));
    return false;
  }
}
const idb = (db, mode, fn) => new Promise((resolve, reject) => {
  const t = db.transaction("kv", mode);
  const r = fn(t.objectStore("kv"));
  t.oncomplete = () => resolve(r?.result);
  t.onerror = () => reject(t.error);
  t.onabort = () => reject(t.error ?? new Error("transaction aborted"));
});
const openDB = (name) => new Promise((resolve, reject) => {
  const q = indexedDB.open(name, 1);
  q.onupgradeneeded = () => q.result.createObjectStore("kv");
  q.onsuccess = () => resolve(q.result);
  q.onerror = () => reject(q.error);
});

async function run() {
  line(null, "Trình duyệt", navigator.userAgent);
  line(null, "Mở từ màn hình chính", String(navigator.standalone === true || matchMedia("(display-mode: standalone)").matches));
  const msg = new TextEncoder().encode("keygate-diag");
  let ed, x, x2, db, back;
  await step("Tạo khóa Ed25519", async () => { ed = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]); });
  await step("Ký Ed25519", async () => `${new Uint8Array(await crypto.subtle.sign("Ed25519", ed.privateKey, msg)).length} byte`);
  await step("Tạo khóa X25519 + deriveBits", async () => {
    x = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    x2 = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return `${(await crypto.subtle.deriveBits({ name: "X25519", public: x2.publicKey }, x.privateKey, 256)).byteLength} byte`;
  });
  await step("Mở IndexedDB", async () => { db = await openDB("keygate-diag"); });
  await step("Lưu CryptoKey Ed25519 vào IndexedDB", () => idb(db, "readwrite", (s) => s.put(ed.privateKey, "ed")));
  await step("Đọc lại CryptoKey", async () => {
    back = await idb(db, "readonly", (s) => s.get("ed"));
    return back ? `${back.algorithm?.name} ${back.type}` : "trống";
  });
  await step("Ký bằng khóa đọc lại", async () => `${new Uint8Array(await crypto.subtle.sign("Ed25519", back, msg)).length} byte`);
  await step("Lưu ArrayBuffer vào IndexedDB", () => idb(db, "readwrite", (s) => s.put(new Uint8Array([1, 2, 3]).buffer, "raw")));
  let xb;
  await step("Lưu CryptoKey X25519 vào IndexedDB", () => idb(db, "readwrite", (s) => s.put(x.privateKey, "x")));
  await step("Đọc lại CryptoKey X25519", async () => {
    xb = await idb(db, "readonly", (s) => s.get("x"));
    return xb ? `${xb.algorithm?.name} ${xb.type}` : `trống (${xb === null ? "null" : typeof xb})`;
  });
  await step("deriveBits bằng khóa X25519 đọc lại", async () => `${(await crypto.subtle.deriveBits({ name: "X25519", public: x2.publicKey }, xb, 256)).byteLength} byte`);
  await step("Dữ liệu ghép đang lưu", async () => {
    const app = await openDB("keygate");
    const keys = await idb(app, "readonly", (s) => s.getAllKeys());
    const phase = await idb(app, "readonly", (s) => s.get("phase"));
    const desc = async (k) => {
      const v = await idb(app, "readonly", (s) => s.get(k));
      return v == null ? `${k}=${v === null ? "null" : "undefined"}` : `${k}=${v.algorithm?.name ?? typeof v}`;
    };
    const ek = await desc("edKey"), xk = await desc("xKey");
    app.close();
    return `phase=${phase ?? "-"}; ${ek}; ${xk}; khóa: ${(keys ?? []).join(",") || "(không có)"}`;
  });
  await step("Mạng: GET /push-key", async () => `HTTP ${(await fetch("/push-key", { cache: "no-store" })).status}`);
  await step("Mạng: request có ký (khóa thử, chờ 401)", async () => {
    const hdr = await P.signRelay(ed.privateKey, "dev_diagdiagdi", "GET", "/v/vlt_diag/members?since=0", P.isoMs(Date.now()), null);
    return `HTTP ${(await fetch("/v/vlt_diag/members?since=0", { headers: hdr, cache: "no-store" })).status}`;
  });
  await step("Lưu trữ bền (persist)", async () => (navigator.storage?.persisted ? String(await navigator.storage.persisted()) : "không hỗ trợ"));
  db?.close();
  line(null, "Xong", "chụp màn hình gửi cho người hỗ trợ");
}

run();
