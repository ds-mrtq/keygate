// KeyGate web app (PWA). No build step, no third-party code. All data reaches the DOM only through
// textContent / createElement (never HTML strings). Layout mirrors prototype giao diện (không kèm repo).
import * as P from "./proto.js";
import * as DB from "./store.js";

const root = document.getElementById("root");
const POLL_MS = 3000;
const FAST_MS = 1500;
const STALE_S = 150;
const B32L = "abcdefghijklmnopqrstuvwxyz234567";
const VAULT_RE = /^[A-Za-z0-9_-]{4,64}$/;
const PIN_RE = /^[A-Za-z2-7-]{20,40}$/;

const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
const isStandalone = () => navigator.standalone === true || matchMedia("(display-mode: standalone)").matches;

// ---------- DOM helpers ----------

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
  }
  for (const c of kids.flat()) {
    if (c == null || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}
let fieldSeq = 0;
/** <label for> bound to el (assigns id/name). */
function lab(text, el, cls) {
  el.id ||= "f" + ++fieldSeq;
  el.name ||= el.id;
  return h("label", { for: el.id, class: cls }, text);
}
const mount = (...nodes) => root.replaceChildren(...nodes);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// RFC 3339 from Go may carry nanoseconds; Safari wants at most milliseconds.
const parseTime = (s) => Date.parse(String(s).replace(/(\.\d{3})\d+/, "$1"));
const pad = (n) => String(n).padStart(2, "0");
const hhmm = (ms) => {
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
};
const hhmmss = (ms) => `${hhmm(ms)}:${pad(new Date(ms).getSeconds())}`;
const ddmmhhmm = (ms) => {
  const d = new Date(ms);
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${hhmm(ms)}`;
};
function ago(sec) {
  const s = Math.max(0, Math.floor(sec));
  return s < 100 ? `${s} giây trước` : `${Math.floor(s / 60)} phút trước`;
}
function lastUsed(unix) {
  if (!unix) return "chưa dùng";
  const now = Date.now(), t = unix * 1000, d = (now - t) / 1000;
  if (d < 3600) return `dùng ${Math.max(1, Math.floor(d / 60))} phút trước`;
  const a = new Date(now), b = new Date(t);
  if (a.toDateString() === b.toDateString()) return `dùng ${hhmm(t)}`;
  const y = new Date(now - 86400000);
  if (y.toDateString() === b.toDateString()) return "dùng hôm qua";
  return `dùng ${pad(b.getDate())}/${pad(b.getMonth() + 1)}`;
}
function randomLabel(alphabet, n) {
  const r = P.randomBytes(n);
  let s = "";
  for (const x of r) s += alphabet[x & 31];
  return s;
}

// ---------- session state ----------

let sess = null; // {vault, pin, dev, label, edKey, xKey, edPub, xPub}
let lastT = 0;
let chain = Promise.resolve();

/** Signed relay request; requests run one at a time so KG-Time stays strictly increasing. */
function signedFetch(method, pathQuery, body) {
  const run = async () => {
    let res;
    for (let attempt = 0; attempt < 2; attempt++) {
      const t = Math.max(Date.now(), lastT + 1);
      lastT = t;
      const hdr = await P.signRelay(sess.edKey, sess.dev, method, pathQuery, P.isoMs(t), body ?? null);
      const init = { method, headers: hdr, cache: "no-store" };
      if (body != null) {
        init.body = body;
        init.headers["Content-Type"] = "text/plain; charset=utf-8";
      }
      // iOS may freeze a request while the app is in the background; a hung fetch would block every
      // later signed request (one-at-a-time chain), so give up after 15 s and let the caller retry.
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), 15000);
      try {
        const r = await fetch(pathQuery, { ...init, signal: ac.signal });
        res = { status: r.status, text: await r.text() };
      } finally {
        clearTimeout(timer);
      }
      if (res.status !== 401) break; // 401 = relay did not process it: retry once with a fresh time
    }
    return res;
  };
  const p = chain.then(run, run);
  chain = p.catch(() => {});
  return p;
}

// ---------- device keys ----------

// iOS 27 Safari keeps an Ed25519 CryptoKey in IndexedDB but an X25519 one reads back as null
// (measured 2026-11-12 with diag.html). The X25519 private key is therefore stored as PKCS#8 sealed
// with a non-extractable AES-GCM key; if even that does not round-trip, as plain PKCS#8 bytes (it
// only opens views; approvals are signed with the Ed25519 key, which stays non-extractable).
async function saveXKey(pkcs8) {
  try {
    const wk = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = P.randomBytes(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wk, pkcs8));
    await DB.setMany({ xWrapKey: wk, xSealed: { iv, ct } });
    if (await loadXKey(await DB.getAll())) return;
  } catch {
    // fall through to plain storage
  }
  await DB.setMany({ xWrapKey: null, xSealed: null, xRaw: new Uint8Array(pkcs8) });
}

/** The X25519 private key from storage, or null when it cannot be recovered. */
async function loadXKey(kv) {
  try {
    let pkcs8 = null;
    if (kv.xWrapKey instanceof CryptoKey && kv.xSealed) {
      pkcs8 = await crypto.subtle.decrypt({ name: "AES-GCM", iv: kv.xSealed.iv }, kv.xWrapKey, kv.xSealed.ct);
    } else if (kv.xRaw) {
      pkcs8 = kv.xRaw;
    } else if (kv.xKey instanceof CryptoKey) {
      return kv.xKey; // browsers that keep X25519 CryptoKeys (pairings made before this change)
    }
    if (!pkcs8) return null;
    return await crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, false, ["deriveBits"]);
  } catch {
    return null;
  }
}

// ---------- link / setup ----------

function parseLink(text) {
  const t = String(text).trim();
  let frag = t;
  const i = t.indexOf("#");
  if (i >= 0) {
    if (i > 0) {
      let u;
      try {
        u = new URL(t);
      } catch {
        throw new Error("Liên kết không đúng. Lấy lại từ khay KeyGate trên laptop (Ghép điện thoại…).");
      }
      if (u.origin !== location.origin) throw new Error("Liên kết thuộc máy chủ khác với trang này.");
    }
    frag = t.slice(i + 1);
  }
  const q = new URLSearchParams(frag);
  const vault = q.get("v") ?? "", pin = q.get("p") ?? "";
  if (!VAULT_RE.test(vault) || !PIN_RE.test(pin)) throw new Error("Liên kết không đúng. Lấy lại từ khay KeyGate trên laptop (Ghép điện thoại…).");
  return { vault, pin };
}

function stepsScreen() {
  const kids = [
    h("h2", null, "KeyGate"),
    h("p", null, "Bước này làm một lần trong Safari."),
    h("ol", { class: "kg-steps" },
      h("li", null, "Bấm nút ", h("b", null, "Chia sẻ"), " ở thanh dưới của Safari."),
      h("li", null, "Chọn ", h("b", null, "Thêm vào Màn hình chính"), "."),
      h("li", null, "Mở ", h("b", null, "KeyGate"), " từ màn hình chính rồi dán liên kết ghép nối.")),
  ];
  if (location.hash.length > 1) {
    const b = h("button", { class: "kg-btn wide kg-full", type: "button" }, "Sao chép liên kết ghép nối");
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(location.href);
        b.textContent = "Đã sao chép";
      } catch {
        b.textContent = "Không sao chép được: chọn và sao chép thanh địa chỉ";
      }
    });
    kids.push(b);
  }
  kids.push(h("p", { class: "kg-note kg-mt" }, "Thông báo đẩy và khóa của thiết bị chỉ hoạt động khi mở từ màn hình chính."));
  mount(h("div", { class: "kg-setup" }, kids));
}

function pairScreen() {
  const link = h("input", { type: "text", placeholder: "Dán liên kết ghép nối", "aria-label": "Liên kết ghép nối", autocomplete: "off", autocapitalize: "off", spellcheck: "false" });
  if (location.hash.length > 1) link.value = location.href;
  const name = h("input", { type: "text", placeholder: "iphone", "aria-label": "Tên thiết bị", maxlength: "64", autocomplete: "off" });
  name.value = "iphone";
  const err = h("div", { class: "kg-warn kg-mt", hidden: true });
  const go = h("button", { class: "kg-btn primary kg-full", type: "button" }, "Bắt đầu");
  const fail = (m) => {
    err.textContent = m;
    err.hidden = false;
    go.disabled = false;
  };
  go.addEventListener("click", async () => {
    err.hidden = true;
    let lk;
    try {
      lk = parseLink(link.value);
    } catch (e) {
      return fail(e.message);
    }
    go.disabled = true;
    try {
      const label = name.value.trim().slice(0, 64) || "iphone";
      let ed, x, xPkcs8;
      try {
        ed = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
        // extractable only long enough to seal it for storage (see saveXKey)
        x = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
        xPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", x.privateKey));
      } catch {
        return fail("Cần iOS 17 trở lên");
      }
      const edPub = await P.rawPublic(ed.publicKey), xPub = await P.rawPublic(x.publicKey);
      const dev = "dev_" + randomLabel(B32L, 10);
      const add = { dev, label, ed_pub: P.b64(edPub), x_pub: P.b64(xPub), role: "approver" };
      const code = P.registrationCode(add);
      const words = await P.codeWords(code);
      let pairCode = "", status = 0;
      for (let i = 0; i < 3; i++) {
        pairCode = randomLabel(B32L, 8).toUpperCase();
        const r = await fetch(`/v/${lk.vault}/pair/${pairCode}`, { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: code });
        status = r.status;
        if (status !== 409) break;
      }
      if (status === 404) return fail("Máy chủ chưa có vault này. Kiểm tra lại liên kết.");
      if (status === 429) return fail("Đang có quá nhiều mã chờ. Thử lại sau vài phút.");
      if (status !== 201) return fail(`Máy chủ từ chối (HTTP ${status}).`);
      await DB.clear();
      await DB.setMany({ vault: lk.vault, pin: lk.pin, dev, label, edKey: ed.privateKey, edPub, xPub, code, pairCode, words });
      await saveXKey(xPkcs8);
      xPkcs8.fill(0);
      const kv = await DB.getAll();
      const xKey = await loadXKey(kv);
      if (!(kv.edKey instanceof CryptoKey) || !xKey) {
        await DB.clear();
        return fail("Máy này không giữ được khóa riêng sau khi lưu. Mở Kiểm tra thiết bị và gửi kết quả cho người cài đặt.");
      }
      await DB.set("phase", "pairing");
      sess = { vault: lk.vault, pin: lk.pin, dev, label, edKey: kv.edKey, xKey, edPub, xPub };
      pairing({ pairCode, words });
    } catch (e) {
      fail("Không kết nối được máy chủ: " + (e?.message ?? e));
    }
  });
  mount(h("div", { class: "kg-setup" },
    h("h2", null, "Ghép với laptop"),
    h("p", null, "Dán liên kết lấy từ khay KeyGate trên laptop (mục “Ghép điện thoại…”)."),
    h("form", { class: "kg-form", onsubmit: (e) => e.preventDefault() },
      lab("Liên kết ghép nối", link), link,
      lab("Tên thiết bị", name), name,
      h("div", { class: "kg-gap" }), go, err),
    h("p", { class: "kg-note" }, "Điện thoại tự tạo khóa riêng và giữ trong máy. Nó không nhận khóa giải mã vault."),
    h("a", { class: "kg-more", href: "diag.html" }, "Kiểm tra thiết bị")));
}

let pairingToken = 0;
function pairing({ pairCode, words }) {
  const token = ++pairingToken;
  const w = words.split(" ");
  const status = h("p", null, h("span", { class: "kg-spin" }), "Đang chờ laptop xác nhận…");
  const again = h("button", { class: "kg-more", type: "button" }, "Hủy và ghép lại");
  again.addEventListener("click", async () => {
    pairingToken++;
    await DB.clear();
    sess = null;
    start();
  });
  mount(h("div", { class: "kg-setup" },
    h("h2", null, "Mã ghép"),
    h("p", null, "Trên laptop chạy lệnh sau rồi so 6 từ. Khác một từ thì dừng."),
    h("div", { class: "kg-pair" }, `${pairCode.slice(0, 4)} ${pairCode.slice(4)}`),
    h("div", { class: "kg-code kg-pair-cmd" }, `kg device add --pair ${pairCode}`),
    h("div", { class: "kg-h kg-h2" }, "6 từ xác nhận"),
    h("div", { class: "kg-words" }, w.slice(0, 3).join(" · "), h("br"), w.slice(3).join(" · ")),
    status, again, h("br"), h("a", { class: "kg-more", href: "diag.html" }, "Kiểm tra thiết bị")));
  (async () => {
    while (token === pairingToken) {
      await sleep(3000);
      if (token !== pairingToken) return;
      try {
        const r = await signedFetch("GET", `/v/${sess.vault}/members?since=0`, null);
        if (r.status !== 200) continue;
        const lines = JSON.parse(r.text).members.sort((a, b) => a.n - b.n).map((m) => m.line);
        const st = await P.verifyMembers(lines, sess.vault, sess.pin);
        P.checkRollback(st, sess.membersMark);
        const me = st.devices.find((d) => d.dev === sess.dev);
        if (me && me.role === "approver" && !me.revoked) {
          await DB.setMany({ phase: "paired", membersCount: st.count, membersHead: st.head });
          const holder = st.devices.find((d) => d.role === "" && !d.revoked);
          pairingToken++;
          paired(holder?.label ?? "Laptop");
          return;
        }
      } catch (e) {
        if (e?.message === P.ROLLBACK_MSG) {
          pairingToken++;
          status.replaceChildren(P.ROLLBACK_MSG);
          status.className = "kg-warn";
          return;
        }
        if (String(e?.message).includes("pin mismatch")) {
          pairingToken++;
          status.replaceChildren("Ghim genesis không khớp");
          status.className = "kg-warn";
          return;
        }
        status.replaceChildren(h("span", { class: "kg-spin" }), "Đang chờ laptop xác nhận… (" + (e?.message ?? e) + ")");
      }
    }
  })();
}

let pushKey = null;
async function pushAvailable() {
  if (!isStandalone() || !("PushManager" in window) || !("serviceWorker" in navigator)) return false;
  try {
    const r = await fetch("/push-key", { cache: "no-store" });
    if (r.status !== 200) return false;
    pushKey = (await r.text()).trim();
    return pushKey.length > 0;
  } catch {
    return false;
  }
}

async function enablePush(report) {
  // requestPermission must run inside the tap handler, before any other await.
  const perm = await Notification.requestPermission();
  if (perm !== "granted") throw new Error("Thông báo chưa được cho phép trong Cài đặt iOS");
  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: P.unb64url(pushKey) });
  const r = await signedFetch("PUT", `/v/${sess.vault}/push/${sess.dev}`, JSON.stringify({ endpoint: sub.endpoint }));
  if (r.status !== 200) throw new Error(`Máy chủ từ chối đăng ký thông báo (HTTP ${r.status})`);
  report?.("Đã bật thông báo");
}

async function paired(laptopLabel) {
  const canPush = await pushAvailable();
  const note = h("p", { class: "kg-note kg-mt" }, "Thông báo chỉ ghi “Có yêu cầu chờ duyệt”. Nội dung yêu cầu chỉ hiện trong app.");
  const later = h("button", { class: "kg-more", type: "button" }, canPush ? "Để sau" : "Tiếp tục");
  later.addEventListener("click", () => start());
  const kids = [h("h2", null, "Đã ghép"), h("p", null, `${laptopLabel} đã nhận điện thoại này làm thiết bị duyệt.`)];
  if (canPush) {
    const b = h("button", { class: "kg-btn primary kg-full", type: "button" }, "Bật thông báo");
    b.addEventListener("click", () => {
      enablePush((m) => (b.textContent = m)).then(() => start(), (e) => {
        note.textContent = e.message;
      });
    });
    kids.push(b, note);
  }
  kids.push(later);
  mount(h("div", { class: "kg-setup" }, kids));
}

// ---------- main: model ----------

let members = null; // verified members state
let netErr = false;
let clockErr = false;
let revoked = false;
const views = new Map(); // from -> {ver, view}
const have = new Map(); // from -> last ver seen (this run only)
const decided = new Map(); // "from/rid" -> result text
const cards = new Map(); // "from/rid" -> {node, p, from, meta}
const waiters = new Map(); // cid -> resolve(result)
let viewsChanged = false;
let sel = null;
let tab = "duyet";
let fastUntil = 0;
let wake = null;
let loopOn = false;
let ui = null;

const keyHolders = () => (members ? members.devices.filter((d) => d.role === "" && !d.revoked) : []);
const current = () => (sel ? views.get(sel)?.view ?? null : null);
const stateOf = (v) => (!v || !v.unlocked ? "locked" : v.session ? "session" : "unlocked");
const livePending = (v) => (v ? v.pending.filter((p) => p.exp * 1000 > Date.now()) : []);

async function loadMembers() {
  const r = await signedFetch("GET", `/v/${sess.vault}/members?since=0`, null);
  if (r.status === 401 || r.status === 403) {
    clockErr = true;
    return false;
  }
  if (r.status !== 200) throw new Error(`members HTTP ${r.status}`);
  clockErr = false;
  const lines = JSON.parse(r.text).members.sort((a, b) => a.n - b.n).map((m) => m.line);
  const st = await P.verifyMembers(lines, sess.vault, sess.pin);
  P.checkRollback(st, sess.membersMark);
  members = st;
  sess.membersMark = { count: st.count, head: st.head };
  await DB.setMany({ membersCount: st.count, membersHead: st.head });
  const me = members.devices.find((d) => d.dev === sess.dev);
  revoked = !me || me.revoked || me.role !== "approver";
  return true;
}

async function handleView({ from, ver, body }) {
  let d = keyHolders().find((x) => x.dev === from);
  if (!d && (await loadMembers())) d = keyHolders().find((x) => x.dev === from);
  have.set(from, ver);
  if (!d) return;
  let obj;
  try {
    const self = { dev: sess.dev, xPriv: sess.xKey, xPub: sess.xPub };
    const o = await P.openEnvelope(sess.vault, self, body, (dev) => (dev === from ? d.edPub : null));
    obj = P.parsePlain(o.plaintext);
  } catch {
    return;
  }
  if (!obj || obj.kind !== "view" || !Array.isArray(obj.pending)) return;
  const old = views.get(from);
  if (old && old.view.time > obj.time) return;
  views.set(from, { ver, view: obj });
  viewsChanged = true;
  if (!sel || !views.has(sel)) sel = from;
  for (const r of obj.results ?? []) {
    const w = waiters.get(r.cid);
    if (w) {
      waiters.delete(r.cid);
      w(r);
    }
  }
}

async function pollOnce() {
  const hv = [...have].map(([k, v]) => `${k}:${v}`).join(",");
  const r = await signedFetch("GET", `/v/${sess.vault}/view/${sess.dev}${hv ? "?have=" + hv : ""}`, null);
  if (r.status === 401 || r.status === 403) {
    clockErr = true;
    return;
  }
  if (r.status !== 200) throw new Error(`view HTTP ${r.status}`);
  clockErr = false;
  for (const v of JSON.parse(r.text).views) await handleView(v);
}

async function sendEnvelope(to, obj) {
  const d = keyHolders().find((x) => x.dev === to);
  if (!d) throw new Error("Không biết máy nhận");
  const id = P.newId();
  const line = await P.sealEnvelope(sess.vault, { dev: sess.dev, edPriv: sess.edKey }, to, d.xPub, JSON.stringify(obj), Date.now(), { id });
  const r = await signedFetch("PUT", `/v/${sess.vault}/msg/${to}/${id}`, line);
  if (r.status === 201) {
    fastUntil = Date.now() + 20000;
    wake?.();
    return;
  }
  if (r.status === 429) throw new Error("Hàng chờ của laptop đang đầy, thử lại sau ít phút");
  if (r.status === 401 || r.status === 403) throw new Error("Đồng hồ điện thoại lệch quá 5 phút hoặc thiết bị đã bị thu hồi");
  throw new Error(`Máy chủ từ chối (HTTP ${r.status})`);
}

/** Sends a command to one machine; resolves with the cid. */
async function sendCommand(to, op, args) {
  const v = views.get(to)?.view;
  const cid = P.newId();
  await sendEnvelope(to, { kind: "command", cid, boot: v ? v.boot : 0, op, args });
  return cid;
}
function waitResult(cid, ms) {
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      waiters.delete(cid);
      resolve(null);
    }, ms);
    waiters.set(cid, (r) => {
      clearTimeout(t);
      resolve(r);
    });
  });
}

async function refreshAll() {
  for (const d of keyHolders()) {
    try {
      await sendCommand(d.dev, "refresh", {});
    } catch {
      /* next poll reports the problem */
    }
  }
}

async function loop() {
  if (loopOn) return;
  loopOn = true;
  let first = true;
  while (loopOn) {
    if (document.visibilityState === "visible") {
      const before = `${netErr}|${clockErr}|${revoked}|${ui.fatal}`;
      viewsChanged = false;
      try {
        if (!members && !(await loadMembers())) throw new Error("clock");
        if (first && members) {
          first = false;
          await refreshAll();
        }
        await pollOnce();
        netErr = false;
      } catch (e) {
        if (e?.message !== "clock") netErr = true;
        if (e?.message === P.ROLLBACK_MSG) {
          loopOn = false;
          clockErr = false;
          members = null;
          ui.fatal = P.ROLLBACK_MSG;
        }
        if (String(e?.message).includes("pin mismatch")) {
          loopOn = false;
          clockErr = false;
          members = null;
          ui.fatal = "Ghim genesis không khớp";
        }
      }
      // Re-render only on change: rebuilding buttons under a finger would swallow the tap.
      if (viewsChanged || before !== `${netErr}|${clockErr}|${revoked}|${ui.fatal}`) renderAll();
    }
    const ms = Date.now() < fastUntil ? FAST_MS : POLL_MS;
    await Promise.race([sleep(ms), new Promise((r) => (wake = r))]);
    wake = null;
  }
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && ui) {
    wake?.();
    refreshAll();
  }
});

// ---------- main: view ----------

const OP_TITLE = {
  grant: "Dùng secret",
  unlock: "Mở khóa vault",
  session: "Mở phiên làm việc",
  "set-file": "Đọc giá trị từ file",
  import: "Nhập secret từ file",
  compare: "So sánh file với vault",
  delete: "Xóa secret",
  "resolve-conflict": "Chọn bản giữ khi xung đột",
};
function opTitle(p) {
  if (p.op === "policy") {
    const m = /v(\d+)/.exec(p.command);
    return m ? `Áp dụng policy.yaml v${m[1]}` : "Áp dụng policy.yaml";
  }
  return OP_TITLE[p.op] ?? p.op;
}
const STATE_TXT = { locked: "Đã khóa", unlocked: "Đã mở, chưa có phiên", session: "Phiên làm việc đang mở" };

function approvalLabel(a) {
  if (!a) return "";
  if (a === "session") return "phiên";
  if (a === "hello" || a === "user-presence") return "Hello";
  if (a.startsWith("remote:")) return "điện thoại";
  if (a.startsWith("paste:")) return "chữ ký thiết bị";
  return a;
}
function grantBy(g) {
  if (g.approval === "session") return "phiên làm việc";
  const by = g.by ?? "";
  if (by === "hello") return "Hello";
  if (by.startsWith("remote:")) return "điện thoại";
  if (by.startsWith("paste:")) return "chữ ký thiết bị";
  if (by === "session") return "phiên làm việc";
  return by || "không cần duyệt";
}

function buildShell() {
  ui = {
    machine: h("span"),
    updated: h("span"),
    dotText: h("span"),
    actions: h("div", { class: "kg-actions" }),
    main: h("div", { class: "kg-main" }),
    tabs: h("nav", { class: "kg-tabs", role: "tablist" }),
    app: null,
    busy: false,
    fatal: "",
    banner: h("div", { class: "kg-warn kg-warn-top", hidden: true }),
    secretFilter: h("input", { class: "kg-search", type: "search", placeholder: "Lọc theo tên", "aria-label": "Lọc theo tên", autocomplete: "off", autocapitalize: "off" }),
    secretList: h("div"),
    form: null,
  };
  ui.secretFilter.id = "kg-filter";
  ui.secretFilter.name = "kg-filter";
  ui.secretFilter.addEventListener("input", renderSecretList);
  ui.app = h("div", { class: "kg-app", "data-state": "locked", "data-pending": "0" },
    h("div", { class: "kg-head" },
      h("div", { class: "kg-machine" }, ui.machine, ui.updated),
      h("div", { class: "kg-state" }, h("span", { class: "kg-dot" }), ui.dotText),
      ui.actions),
    ui.main, ui.tabs);
  buildTabs();
  mount(ui.app);
}

const TABS = [["duyet", "Duyệt"], ["secret", "Secret"], ["grant", "Grant"], ["log", "Nhật ký"], ["them", "Thêm"]];
function buildTabs() {
  ui.tabBtns = new Map();
  for (const [k, t] of TABS) {
    const badge = h("span", { class: "kg-badge", hidden: true });
    const b = h("button", { class: "kg-tab", role: "tab", type: "button", "aria-selected": String(tab === k) }, t, k === "duyet" ? badge : null);
    b.addEventListener("click", () => {
      tab = k;
      renderAll();
    });
    ui.tabBtns.set(k, { b, badge });
    ui.tabs.append(b);
  }
}

function renderAll() {
  if (!ui) return;
  const v = current();
  const st = stateOf(v);
  const open = livePending(v).filter((p) => !decided.has(`${sel}/${p.rid}`)).length;
  ui.app.dataset.state = st;
  ui.app.dataset.pending = open ? "1" : "0";
  renderHead(v, st);
  for (const [k, { b, badge }] of ui.tabBtns) {
    b.setAttribute("aria-selected", String(tab === k));
    if (k === "duyet") {
      badge.hidden = !open;
      badge.textContent = String(open);
    }
  }
  let msg = "";
  if (ui.fatal) msg = ui.fatal;
  else if (revoked) msg = "Thiết bị này không còn là thiết bị duyệt của vault (đã bị thu hồi). Ghép lại nếu cần.";
  else if (clockErr) msg = "Đồng hồ điện thoại lệch quá 5 phút hoặc thiết bị đã bị thu hồi";
  else if (netErr) msg = "Mất kết nối tới máy chủ relay. Đang thử lại.";
  ui.banner.textContent = msg;
  ui.banner.hidden = !msg;

  const pane = [ui.banner];
  if (tab === "duyet") pane.push(...paneDuyet(v, st));
  else if (tab === "secret") pane.push(...paneSecret(v));
  else if (tab === "grant") pane.push(...paneGrant(v));
  else if (tab === "log") pane.push(...paneLog(v));
  else pane.push(...paneThem(v));
  ui.main.replaceChildren(...pane);
}

function renderHead(v, st) {
  // machine label (select when several machines report)
  if (views.size > 1) {
    const s = h("select", { "aria-label": "Chọn máy" });
    for (const [from, { view }] of views) {
      const o = h("option", { value: from }, view.label);
      if (from === sel) o.selected = true;
      s.append(o);
    }
    s.addEventListener("change", () => {
      sel = s.value;
      DB.set("sel", sel).catch(() => {});
      renderAll();
    });
    ui.machine.replaceChildren(s);
  } else {
    ui.machine.replaceChildren(v ? v.label : "");
  }
  ui.dotText.textContent = v ? STATE_TXT[st] : "Đang chờ laptop…";
  tickHead();

  const btn = (text, cls, op) => {
    const b = h("button", { class: `kg-btn ${cls}`, type: "button" }, text);
    b.disabled = ui.busy;
    b.addEventListener("click", () => command(op, text));
    return b;
  };
  const acts = [];
  if (v) {
    if (st === "session") acts.push(btn("Kết thúc phiên", "wide", "session-end"), btn("Khóa", "danger", "lock"));
    else if (st === "unlocked") acts.push(btn("Mở phiên làm việc", "primary wide", "session-start"), btn("Khóa", "danger", "lock"));
    else acts.push(btn("Mở khóa + mở phiên", "primary wide", "session-start"));
  }
  ui.actions.replaceChildren(...acts);
}

function tickHead() {
  const v = current();
  if (!v) {
    ui.updated.className = "";
    ui.updated.textContent = "";
    return;
  }
  const age = (Date.now() - v.time) / 1000;
  if (age > STALE_S) {
    ui.updated.className = "stale";
    ui.updated.textContent = "Máy không phản hồi";
  } else {
    ui.updated.className = "";
    ui.updated.textContent = "cập nhật " + ago(age);
  }
}

async function command(op, text) {
  if (!sel || ui.busy) return;
  ui.busy = true;
  renderAll();
  try {
    await sendCommand(sel, op, {});
  } catch (e) {
    ui.banner.textContent = e.message;
    ui.banner.hidden = false;
  }
  setTimeout(() => {
    ui.busy = false;
    renderAll();
  }, 1500);
}

// ---- tab Duyệt ----

function paneDuyet(v, st) {
  const list = livePending(v);
  const keep = new Set(list.map((p) => `${sel}/${p.rid}`));
  for (const k of [...cards.keys()]) if (!keep.has(k)) cards.delete(k);
  if (!v || list.length === 0) {
    const sub = !v ? "Laptop chưa gửi trạng thái. Kiểm tra KeyGate đang chạy trên laptop."
      : st === "session" ? "Agent đang tự dùng secret trong phiên. Khóa màn hình laptop không làm gián đoạn."
      : st === "locked" ? "Vault đang khóa. Agent sẽ hỏi ở đây khi cần mở."
      : "Chưa có phiên: cặp secret–lệnh mới sẽ hỏi ở đây một lần.";
    return [h("div", { class: "kg-empty" }, h("b", null, "Không có yêu cầu chờ"), sub)];
  }
  const out = [h("div", { class: "kg-h" }, "Yêu cầu chờ duyệt")];
  for (const p of list.sort((a, b) => a.created - b.created)) {
    const key = `${sel}/${p.rid}`;
    let c = cards.get(key);
    if (!c) {
      c = buildCard(sel, p);
      cards.set(key, c);
    }
    out.push(c.node);
  }
  return out;
}

function metaText(p) {
  const now = Date.now() / 1000;
  const left = Math.max(1, Math.ceil((p.exp - now) / 60));
  return [p.agent, p.peer, ago(now - p.created), `hết hạn sau ${left} phút`].filter(Boolean).join(" · ");
}
function tickCards() {
  for (const c of cards.values()) if (c.meta) c.meta.textContent = metaText(c.p);
}

function diffNode(detail) {
  const box = h("div", { class: "kg-diff", hidden: true });
  for (const line of detail.split("\n")) {
    let cls = "";
    if (line.startsWith("!") || line.includes("CẢNH BÁO")) cls = "warn";
    else if (line.startsWith("+")) cls = "add";
    else if (line.startsWith("-")) cls = "del";
    box.append(h("div", { class: cls || null }, line === "" ? "\u00a0" : line));
  }
  return box;
}

function buildCard(from, p) {
  const key = `${from}/${p.rid}`;
  const node = h("div", { class: "kg-req" });
  const meta = h("div", { class: "kg-meta" }, metaText(p));
  const c = { node, p, meta, from };
  const doneText = decided.get(key);
  if (doneText) {
    showDone(c, doneText);
    return c;
  }
  const kids = [
    h("div", { class: "kg-req-top" }, h("span", { class: "kg-req-op" }, opTitle(p)), p.prod ? h("span", { class: "kg-prod" }, "PROD") : null),
    ...p.secrets.map((s) => h("div", { class: "kg-req-sec" }, s)),
    h("div", { class: "kg-code" }, p.command),
    meta,
  ];
  if (p.detail) {
    const box = diffNode(p.detail);
    const more = h("button", { class: "kg-more", type: "button" }, "Chi tiết (diff và cảnh báo)");
    more.addEventListener("click", () => {
      box.hidden = !box.hidden;
      more.textContent = box.hidden ? "Chi tiết (diff và cảnh báo)" : "Ẩn chi tiết";
    });
    kids.push(more, box);
  }
  const err = h("div", { class: "kg-result", hidden: true });
  const btns = [];
  const mk = (text, cls, choice) => {
    const b = h("button", { class: cls, type: "button" }, text);
    b.addEventListener("click", () => decide(c, choice, btns, err));
    btns.push(b);
    return b;
  };
  const row = h("div", { class: "kg-req-btns" });
  if (p.choices.includes("deny")) row.append(mk("Từ chối", "kg-btn danger", "deny"));
  if (p.choices.includes("allow")) row.append(mk("Cho phép", "kg-btn primary wide", "allow"));
  kids.push(row);
  if (p.op === "grant") kids.push(h("div", { class: "kg-meta kg-mt6" }, "Cho phép: nhớ đến khi thu hồi, lần sau không hỏi lại cặp secret–lệnh này."));
  if (p.choices.includes("session")) kids.push(mk("Cho phép và mở phiên làm việc (không hỏi gì nữa)", "kg-more kg-req-alt", "session"));
  kids.push(err);
  node.replaceChildren(...kids.flat());
  return c;
}

function showDone(c, text) {
  c.node.className = "kg-req done";
  c.meta = null;
  c.node.replaceChildren(h("div", { class: "kg-req-op" }, opTitle(c.p)), h("div", { class: "kg-result" }, text));
}

async function decide(c, choice, btns, err) {
  for (const b of btns) b.disabled = true;
  err.hidden = true;
  try {
    const digest = await P.pendingDigest(c.p);
    await sendEnvelope(c.from, { kind: "decision", rid: c.p.rid, digest, choice });
    const text = choice === "deny" ? "Đã từ chối · vừa xong" : choice === "session" ? "Đã cho phép và mở phiên · vừa xong" : "Đã cho phép · vừa xong";
    decided.set(`${c.from}/${c.p.rid}`, text);
    showDone(c, text);
    renderAll();
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
    for (const b of btns) b.disabled = false;
  }
}

// ---- tab Secret ----

function renderSecretList() {
  const v = current();
  const q = ui.secretFilter.value.trim().toLowerCase();
  const rows = (v?.secrets ?? []).filter((s) => !q || s.name.toLowerCase().includes(q));
  ui.secretList.replaceChildren(
    ...rows.map((s) => h("div", { class: "kg-row" },
      h("div", null, h("div", { class: "kg-row-name" }, s.name), h("div", { class: "kg-row-sub" }, `${s.kind} · ${s.env} · ${lastUsed(s.last_used)}`)),
      s.prod ? h("span", { class: "kg-prod" }, "PROD") : null)),
    h("p", { class: "kg-note" }, "Chỉ có tên và thông tin mô tả. Giá trị không bao giờ rời laptop."));
}
function paneSecret(v) {
  if (!v || !v.unlocked) return [h("div", { class: "kg-empty" }, h("b", null, "Vault đang khóa"), "Mở khóa để xem danh sách tên secret.")];
  renderSecretList();
  return [ui.secretFilter, ui.secretList];
}

// ---- tab Grant ----

function paneGrant(v) {
  const gs = v?.grants ?? [];
  const out = [h("div", { class: "kg-h" }, "Grant đang nhớ")];
  if (gs.length === 0) out.push(h("p", { class: "kg-note" }, "Chưa có grant nào được nhớ."));
  for (const g of gs) {
    const exp = g.expires ? `hết hạn ${hhmm(parseTime(g.expires))}` : "không hết hạn";
    const b = h("button", { class: "kg-link", type: "button" }, "Thu hồi");
    b.addEventListener("click", () => revoke(b, { secret: g.secret, pattern: g.pattern, path: g.path }));
    out.push(h("div", { class: "kg-row" },
      h("div", null,
        h("div", { class: "kg-row-name" }, g.secret),
        h("div", { class: "kg-row-sub kg-mono" }, g.pattern),
        h("div", { class: "kg-row-sub" }, `${grantBy(g)} · ${ddmmhhmm(parseTime(g.at))} · ${exp}`)),
      b));
  }
  if (gs.length) {
    const all = h("button", { class: "kg-btn danger kg-full", type: "button" }, "Thu hồi tất cả");
    all.addEventListener("click", () => revoke(all, { all: true }));
    out.push(h("div", { class: "kg-mt" }, all));
  }
  return out;
}
async function revoke(btn, args) {
  btn.disabled = true;
  try {
    await sendCommand(sel, "grant-revoke", args);
    btn.textContent = "Đã gửi";
  } catch (e) {
    btn.disabled = false;
    ui.banner.textContent = e.message;
    ui.banner.hidden = false;
  }
}

// ---- tab Nhật ký ----

function paneLog(v) {
  const rows = [...(v?.audit ?? [])].sort((a, b) => b.time - a.time);
  const out = [h("div", { class: "kg-h" }, "50 dòng gần nhất")];
  for (const a of rows) {
    const sub = [approvalLabel(a.approval), a.agent, a.event === "run" ? `exit ${a.exit}` : ""].filter(Boolean).join(" · ");
    out.push(h("div", { class: "kg-log" },
      h("time", null, hhmm(a.time * 1000)),
      h("div", null, h("b", null, a.event), a.secret ? " " : null, a.secret ? h("span", { class: "kg-mono" }, a.secret) : null, h("div", { class: "kg-row-sub" }, sub))));
  }
  if (rows.length === 0) out.push(h("p", { class: "kg-note" }, "Chưa có dòng nhật ký."));
  return out;
}

// ---- tab Thêm ----

function buildForm() {
  const inp = (label, attrs) => {
    const el = h("input", { type: "text", autocomplete: "off", autocapitalize: "off", spellcheck: "false", "aria-label": label, ...attrs });
    return el;
  };
  const sel_ = (label, opts) => {
    const s = h("select", { "aria-label": label }, opts.map((o) => h("option", { value: o }, o)));
    return s;
  };
  const f = {
    name: inp("Tên", { placeholder: "vd: app/test-db-password" }),
    env: sel_("Môi trường", ["dev", "test", "prod"]),
    kind: sel_("Kind", ["env", "file", "template", "oracle-wallet"]),
    envName: inp("Tên biến môi trường", { placeholder: "DB_PASSWORD" }),
    tns: inp("TNS alias", {}),
    user: inp("User", {}),
    value: h("input", { type: "password", placeholder: "gõ hoặc dán", "aria-label": "Giá trị", autocomplete: "off", autocapitalize: "off" }),
    over: h("input", { type: "checkbox", id: "kg-over", name: "kg-over" }),
    btn: h("button", { class: "kg-btn primary kg-full", type: "button" }, "Lưu vào vault trên laptop"),
    warn: h("div", { class: "kg-warn", hidden: true }, "Vault đang khóa: mở khóa trước khi thêm secret."),
    err: h("div", { class: "kg-warn", hidden: true }),
    note: h("p", { class: "kg-note" }),
    wallet: h("div", { class: "two", hidden: true }),
    pushBtn: h("button", { class: "kg-more", type: "button", hidden: true }, "Bật thông báo"),
  };
  f.wallet.append(h("div", null, lab("TNS alias", f.tns), f.tns), h("div", null, lab("User", f.user), f.user));
  f.kind.addEventListener("change", () => (f.wallet.hidden = f.kind.value !== "oracle-wallet"));
  f.btn.addEventListener("click", submitSecret);
  f.pushBtn.addEventListener("click", () => {
    enablePush(() => (f.pushBtn.hidden = true)).catch((e) => {
      f.err.textContent = e.message;
      f.err.hidden = false;
    });
  });
  f.node = h("form", { class: "kg-form", onsubmit: (e) => e.preventDefault() },
    f.warn,
    lab("Tên", f.name), f.name,
    h("div", { class: "two" }, h("div", null, lab("Môi trường", f.env), f.env), h("div", null, lab("Kind", f.kind), f.kind)),
    lab("Tên biến môi trường", f.envName), f.envName,
    f.wallet,
    lab("Giá trị", f.value), f.value,
    h("label", { class: "kg-check" }, f.over, " Ghi đè nếu đã có"),
    f.btn, f.err, f.note, f.pushBtn);
  return f;
}

function paneThem(v) {
  ui.form ??= buildForm();
  const f = ui.form;
  const locked = !v || !v.unlocked;
  f.warn.hidden = !locked;
  if (!f.sending) f.btn.disabled = locked;
  f.note.textContent = `Giá trị được mã hóa cho riêng ${v ? v.label : "laptop"} trước khi rời điện thoại. Máy chủ chỉ chuyển bản mã.`;
  if (f.pushChecked !== true && isStandalone() && "PushManager" in window && "serviceWorker" in navigator) {
    f.pushChecked = true;
    navigator.serviceWorker.ready
      .then((reg) => reg.pushManager.getSubscription())
      .then(async (sub) => {
        if (!sub && (await pushAvailable())) {
          f.pushBtn.hidden = false;
        }
      })
      .catch(() => {});
  }
  return [f.node];
}

async function submitSecret() {
  const f = ui.form;
  const name = f.name.value.trim(), value = f.value.value;
  f.err.hidden = true;
  if (!name || value === "") {
    f.err.textContent = "Nhập tên và giá trị.";
    f.err.hidden = false;
    return;
  }
  f.sending = true;
  f.btn.disabled = true;
  f.btn.textContent = "Đang gửi…";
  const args = {
    name, kind: f.kind.value, env: f.env.value, env_name: f.envName.value.trim(),
    tns_alias: f.kind.value === "oracle-wallet" ? f.tns.value.trim() : "",
    user: f.kind.value === "oracle-wallet" ? f.user.value.trim() : "",
    desc: "", value, overwrite: f.over.checked,
  };
  f.value.value = ""; // the value never stays in the form
  try {
    const cid = await sendCommand(sel, "set", args);
    const r = await waitResult(cid, 45000);
    if (!r) throw new Error("Laptop chưa trả lời. Kiểm tra lại sau.");
    if (!r.ok) throw new Error(r.msg || "Laptop từ chối");
    f.btn.textContent = `Đã lưu: ${name}`;
  } catch (e) {
    f.err.textContent = e.message;
    f.err.hidden = false;
    f.btn.textContent = "Lưu vào vault trên laptop";
  }
  setTimeout(() => {
    f.sending = false;
    f.btn.textContent = "Lưu vào vault trên laptop";
    f.btn.disabled = !current()?.unlocked;
  }, 4000);
}

// ---------- boot ----------

async function startMain(kv, xKey) {
  sess = { vault: kv.vault, pin: kv.pin, dev: kv.dev, label: kv.label, edKey: kv.edKey, xKey, edPub: kv.edPub, xPub: kv.xPub, membersMark: kv.membersCount ? { count: kv.membersCount, head: kv.membersHead } : null };
  sel = kv.sel ?? null;
  buildShell();
  renderAll();
  loop();
}

/** Stored keys can no longer be read (pairing made before the iOS 27 X25519 workaround). */
function keysLostScreen() {
  const again = h("button", { class: "kg-btn primary kg-full", type: "button" }, "Ghép lại");
  again.addEventListener("click", async () => {
    await DB.clear();
    sess = null;
    start();
  });
  mount(h("div", { class: "kg-setup" },
    h("h2", null, "Cần ghép lại"),
    h("p", null, "Khóa riêng của điện thoại không đọc lại được (bản cũ của app lưu khóa theo cách iOS không giữ). Bấm Ghép lại để tạo khóa mới, rồi trên laptop chạy kg device add --pair như lần trước."),
    again,
    h("a", { class: "kg-more", href: "diag.html" }, "Kiểm tra thiết bị")));
}

async function start() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js", { scope: "/app/" }).catch(() => {});
  const kv = await DB.getAll();
  if (kv.phase === "paired" || kv.phase === "pairing") {
    const xKey = await loadXKey(kv);
    if (!(kv.edKey instanceof CryptoKey) || !xKey) return keysLostScreen();
    if (kv.phase === "paired") return startMain(kv, xKey);
    sess = { vault: kv.vault, pin: kv.pin, dev: kv.dev, label: kv.label, edKey: kv.edKey, xKey, edPub: kv.edPub, xPub: kv.xPub, membersMark: kv.membersCount ? { count: kv.membersCount, head: kv.membersHead } : null };
    return pairing({ pairCode: kv.pairCode, words: kv.words });
  }
  if (isIOS && !isStandalone()) return stepsScreen();
  pairScreen();
}

setInterval(() => {
  if (!ui) return;
  tickHead();
  tickCards();
}, 1000);

start().catch((e) => {
  mount(h("div", { class: "kg-setup" }, h("h2", null, "KeyGate"), h("p", { class: "kg-warn" }, "Không khởi động được: " + (e?.message ?? e))));
});
