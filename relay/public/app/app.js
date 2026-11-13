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
  const vault = q.get("v") ?? "", pin = q.get("p") ?? "", c = q.get("c") ?? "", n = q.get("n") ?? "";
  const bad = () => new Error("Liên kết không đúng. Lấy lại từ khay KeyGate trên laptop (Ghép điện thoại…).");
  if (!VAULT_RE.test(vault) || !PIN_RE.test(pin) || !/^[A-Z2-7]{16}$/.test(c)) throw bad();
  try {
    if (P.unb64url(n).length !== 16) throw bad();
  } catch {
    throw bad();
  }
  return { vault, pin, c, n };
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
      const words = await P.pairWords(code, lk.n);
      const r = await fetch(`/v/${lk.vault}/pair/${lk.c}`, { method: "PUT", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: code });
      if (r.status === 404) return fail("Mã ghép hết hạn hoặc không đúng. Trên laptop mở lại Ghép điện thoại… rồi dùng liên kết mới.");
      if (r.status === 409) return fail("Mã ghép đã được dùng. Trên laptop mở lại Ghép điện thoại… rồi dùng liên kết mới.");
      if (r.status !== 201) return fail(`Máy chủ từ chối (HTTP ${r.status}).`);
      await DB.clear();
      await DB.setMany({ vault: lk.vault, pin: lk.pin, dev, label, edKey: ed.privateKey, edPub, xPub, code, words });
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
      pairing({ words });
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
function pairing({ words }) {
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
    h("h2", null, "Xác nhận trên laptop"),
    h("p", null, "Laptop đang hiện 6 từ. So với 6 từ dưới đây: khác một từ thì dừng, không bấm đồng ý trên laptop."),
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
let adding = false; // Secret tab shows the add form instead of the list
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
const OP_ICON = { grant: "key", unlock: "unlock", session: "bolt", "set-file": "doc", import: "doc", compare: "doc", delete: "trash", "resolve-conflict": "alert", policy: "doc" };
function opTitle(p) {
  if (p.op === "policy") {
    const m = /v(\d+)/.exec(p.command);
    return m ? `Áp dụng policy.yaml v${m[1]}` : "Áp dụng policy.yaml";
  }
  return OP_TITLE[p.op] ?? p.op;
}
const STATE_TXT = { locked: "Đã khóa", unlocked: "Đã mở, chưa có phiên", session: "Phiên làm việc đang mở" };
const STATE_ICON = { locked: "lock", unlocked: "unlock", session: "bolt" };
function stateSub(v, st) {
  if (!v) return "Chờ laptop gửi trạng thái.";
  if (st === "locked") return "Agent bị từ chối cho tới khi mở khóa.";
  if (st === "session") return `Mở từ ${hhmm(v.session.start * 1000)} · agent tự dùng secret, không hỏi.`;
  return "Grant đã nhớ chạy ngay; cặp secret–lệnh mới phải duyệt.";
}

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
/** Same rule as policy.IsProd: a name segment "prod"/"prd", or env prod. */
const isProdName = (n) => n.toLowerCase().split(/[^a-z0-9]+/).some((s) => s === "prod" || s === "prd");
const envOf = (s) => (s.prod ? "prod" : s.env);
const ENV_TONE = { prod: "bad", test: "warn" };
/** "hôm nay 10:33" style stamp: time only for today, date + time otherwise. */
const stamp = (ms) => (new Date(ms).toDateString() === new Date().toDateString() ? hhmm(ms) : ddmmhhmm(ms));
function dayLabel(ms) {
  const d = new Date(ms).toDateString();
  if (d === new Date().toDateString()) return "Hôm nay";
  if (d === new Date(Date.now() - 86400000).toDateString()) return "Hôm qua";
  const x = new Date(ms);
  return `${pad(x.getDate())}/${pad(x.getMonth() + 1)}/${x.getFullYear()}`;
}

// ---------- icons and small parts ----------

const ICONS = {
  duyet: ["M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6z", "M9 12l2 2 4-4"],
  secret: ["M8 10.5a5 5 0 1 0 0 10a5 5 0 1 0 0-10z", "M11.5 12.5L20 4", "M17 7l2.5 2.5", "M14.5 9.5l2 2"],
  key: ["M8 10.5a5 5 0 1 0 0 10a5 5 0 1 0 0-10z", "M11.5 12.5L20 4", "M17 7l2.5 2.5", "M14.5 9.5l2 2"],
  grant: ["M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1", "M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"],
  unlink: ["M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1", "M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1", "M4 4l16 16"],
  log: ["M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z", "M12 7v5l3 2"],
  lock: ["M5 11h14v10H5z", "M8 11V8a4 4 0 0 1 8 0v3"],
  unlock: ["M5 11h14v10H5z", "M8 11V8a4 4 0 0 1 7.7-1.5"],
  bolt: ["M13 3L5 14h6l-1 7 8-11h-6z"],
  search: ["M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14z", "M20 20l-4.2-4.2"],
  plus: ["M12 5v14", "M5 12h14"],
  back: ["M15 5l-7 7 7 7"],
  sort: ["M7 4v16", "M4 17l3 3 3-3", "M17 20V4", "M14 7l3-3 3 3"],
  env: ["M4 6l5 6-5 6", "M12 18h8"],
  file: ["M6 3h8l4 4v14H6z", "M14 3v4h4"],
  template: ["M9 4H8a3 3 0 0 0-3 3v2a3 3 0 0 1-2 3a3 3 0 0 1 2 3v2a3 3 0 0 0 3 3h1", "M15 4h1a3 3 0 0 1 3 3v2a3 3 0 0 0 2 3a3 3 0 0 0-2 3v2a3 3 0 0 1-3 3h-1"],
  wallet: ["M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z", "M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6", "M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"],
  play: ["M8 5v14l11-7z"],
  x: ["M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z", "M9 9l6 6", "M15 9l-6 6"],
  check: ["M5 12l5 5 9-10"],
  trash: ["M4 7h16", "M9 7V4h6v3", "M6 7l1 13h10l1-13"],
  doc: ["M6 3h8l4 4v14H6z", "M14 3v4h4", "M9 13h6", "M9 17h6"],
  eye: ["M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z", "M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6z"],
  phone: ["M7 2h10v20H7z", "M11 18h2"],
  alert: ["M12 3l10 18H2z", "M12 10v5", "M12 18v.5"],
  folder: ["M3 6h6l2 2h10v11H3z"],
  bell: ["M6 16v-5a6 6 0 0 1 12 0v5l2 2H4z", "M10 20a2 2 0 0 0 4 0"],
  shield: ["M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6z"],
};
const KIND_ICON = { env: "env", file: "file", template: "template", "oracle-wallet": "wallet" };
function icon(name, cls) {
  const NS = "http://www.w3.org/2000/svg";
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("aria-hidden", "true");
  s.setAttribute("class", cls ? `kg-ico ${cls}` : "kg-ico");
  for (const d of ICONS[name] ?? ICONS.doc) {
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", d);
    s.append(p);
  }
  return s;
}
const tone = (t) => (t ? ` t-${t}` : "");
const tile = (name, t) => h("span", { class: "kg-tile" + tone(t) }, icon(name));
const chip = (text, t, cls) => h("span", { class: "kg-chip" + tone(t) + (cls ? " " + cls : "") }, text);
function emptyState(ico, t, title, sub) {
  return h("div", { class: "kg-empty" }, h("span", { class: "kg-empty-ico" + tone(t) }, icon(ico)), h("b", null, title), sub);
}
function section(label, n) {
  return h("div", { class: "kg-sec" }, h("span", null, label), n == null ? null : h("span", { class: "kg-sec-n" }, String(n)));
}
/** Native <select> dressed as a small "↕ label" control; the iOS picker does the work. */
function sortBox(label, opts, onChange) {
  const s = h("select", { "aria-label": label }, opts.map(([v, t]) => h("option", { value: v }, t)));
  s.addEventListener("change", () => onChange(s.value));
  const node = h("label", { class: "kg-sortbox" }, icon("sort"), s);
  return { node, select: s };
}
/** iOS-style segmented control. */
function segmented(label, opts, value, onChange) {
  const node = h("div", { class: "kg-seg", role: "radiogroup", "aria-label": label });
  let cur = value;
  const btns = opts.map(([v, t, cls]) => {
    const b = h("button", { type: "button", role: "radio", class: "kg-seg-b" + (cls ? " " + cls : "") }, t);
    b.addEventListener("click", () => {
      set(v);
      onChange?.(v);
    });
    node.append(b);
    return [v, b];
  });
  const set = (v) => {
    cur = v;
    for (const [k, b] of btns) b.setAttribute("aria-checked", String(k === v));
  };
  set(value);
  return { node, get value() { return cur; }, set value(v) { set(v); } };
}

// ---------- shell ----------

function buildShell() {
  ui = {
    machine: h("span", { class: "kg-machine-name" }),
    updated: h("span"),
    dotText: h("div", { class: "kg-state" }),
    stSub: h("div", { class: "kg-st-sub" }),
    stIco: h("span", { class: "kg-st-ico" }),
    actions: h("div", { class: "kg-actions" }),
    main: h("div", { class: "kg-main" }),
    tabs: h("nav", { class: "kg-tabs", role: "tablist" }),
    app: null,
    busy: false,
    fatal: "",
    banner: h("div", { class: "kg-warn", hidden: true }),
    secretCount: h("span", { class: "kg-title-n" }),
    secretFilter: h("input", { class: "kg-search", type: "search", placeholder: "Tìm theo tên", "aria-label": "Tìm theo tên", autocomplete: "off", autocapitalize: "off", spellcheck: "false" }),
    secretChips: h("div", { class: "kg-chips" }),
    secretEnv: "all",
    secretList: h("div"),
    flash: "",
    grantCount: h("span", { class: "kg-title-n" }),
    logSeg: null,
    pushBtn: h("button", { class: "kg-btn kg-full kg-mt kg-btn-ico", type: "button", hidden: true }, icon("bell"), "Bật thông báo khi có yêu cầu"),
    form: null,
  };
  const add = h("button", { class: "kg-pill", type: "button" }, icon("plus"), "Thêm");
  add.addEventListener("click", () => {
    adding = true;
    renderAll();
  });
  const ss = sortBox("Sắp xếp secret", [["name", "Nhóm"], ["recent", "Gần đây"], ["env", "Môi trường"]], (v) => {
    DB.set("secretSort", v).catch(() => {});
    renderSecretList();
  });
  ui.secretSort = ss.select;
  ui.secretHead = h("div", { class: "kg-hrow" }, h("div", { class: "kg-title" }, "Secret", ui.secretCount), ss.node, add);
  ui.secretSearch = h("div", { class: "kg-searchbox" }, icon("search"), ui.secretFilter);
  ui.secretTools = h("div", { class: "kg-tools" }, ui.secretChips);
  ui.secretFilter.id = "kg-filter";
  ui.secretFilter.name = "kg-filter";
  ui.secretFilter.addEventListener("input", renderSecretList);
  const gs = sortBox("Sắp xếp grant", [["new", "Mới nhất"], ["secret", "Theo secret"], ["exp", "Sắp hết hạn"]], () => renderAll());
  ui.grantSort = gs.select;
  ui.grantHead = h("div", { class: "kg-hrow" }, h("div", { class: "kg-title" }, "Grant", ui.grantCount), gs.node);
  ui.logSeg = segmented("Lọc nhật ký", [["all", "Tất cả"], ["run", "Chạy"], ["change", "Thay đổi"], ["deny", "Từ chối"]], "all", () => renderAll());
  ui.logHead = h("div", { class: "kg-hrow" }, h("div", { class: "kg-title" }, "Nhật ký"));
  ui.app = h("div", { class: "kg-app", "data-state": "locked", "data-pending": "0" },
    h("header", { class: "kg-head" },
      h("div", { class: "kg-top" },
        h("img", { class: "kg-logo", src: "icon.svg", alt: "" }),
        h("b", { class: "kg-brand" }, "KeyGate"),
        h("div", { class: "kg-machine" }, ui.machine, ui.updated)),
      h("div", { class: "kg-hero" }, ui.stIco, h("div", { class: "kg-hero-txt" }, ui.dotText, ui.stSub)),
      ui.actions),
    ui.main, ui.tabs);
  buildTabs();
  mount(ui.app);
  pushInit();
}

/** Offers the push opt-in on the Duyệt tab while this installed app has no subscription. */
function pushInit() {
  ui.pushBtn.addEventListener("click", () => {
    enablePush(() => (ui.pushBtn.hidden = true)).catch((e) => {
      ui.banner.textContent = e.message;
      ui.banner.hidden = false;
    });
  });
  if (!isStandalone() || !("PushManager" in window) || !("serviceWorker" in navigator)) return;
  navigator.serviceWorker.ready
    .then((reg) => reg.pushManager.getSubscription())
    .then(async (sub) => {
      if (!sub && (await pushAvailable())) ui.pushBtn.hidden = false;
    })
    .catch(() => {});
}

const TABS = [["duyet", "Duyệt"], ["secret", "Secret"], ["grant", "Grant"], ["log", "Nhật ký"]];
function buildTabs() {
  ui.tabBtns = new Map();
  for (const [k, t] of TABS) {
    const badge = h("span", { class: "kg-badge", hidden: true });
    const b = h("button", { class: "kg-tab", role: "tab", type: "button", "aria-selected": String(tab === k) },
      h("span", { class: "kg-tab-ico" }, icon(k), badge), t);
    b.addEventListener("click", () => {
      // tapping Secret again leaves the add form, like an iOS tab bar returns to its root
      if (k === "secret" && tab === "secret") adding = false;
      const changed = tab !== k;
      tab = k;
      renderAll();
      if (changed) {
        ui.main.scrollTop = 0;
        ui.main.classList.remove("kg-enter");
        void ui.main.offsetWidth; // restart the entry animation
        ui.main.classList.add("kg-enter");
      }
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
  const conflicts = v?.unlocked ? (v.secrets ?? []).filter((s) => s.conflict).length : 0;
  ui.app.dataset.state = st;
  ui.app.dataset.pending = open ? "1" : "0";
  renderHead(v, st);
  for (const [k, { b, badge }] of ui.tabBtns) {
    b.setAttribute("aria-selected", String(tab === k));
    const n = k === "duyet" ? open : k === "secret" ? conflicts : 0;
    badge.hidden = !n;
    badge.textContent = String(n);
    badge.className = k === "secret" ? "kg-badge bad" : "kg-badge";
  }
  let msg = "";
  if (ui.fatal) msg = ui.fatal;
  else if (revoked) msg = "Thiết bị này không còn là thiết bị duyệt của vault (đã bị thu hồi). Ghép lại nếu cần.";
  else if (clockErr) msg = "Đồng hồ điện thoại lệch quá 5 phút hoặc thiết bị đã bị thu hồi";
  else if (netErr) msg = "Mất kết nối tới máy chủ relay. Đang thử lại.";
  else if (v && v.unlocked && v.policy_ok === false) msg = "policy.yaml trên laptop đã sửa mà chưa áp dụng: mọi grant bị từ chối tới khi chạy kg policy apply.";
  ui.banner.textContent = msg;
  ui.banner.hidden = !msg;

  const pane = [ui.banner];
  if (tab === "duyet") pane.push(...paneDuyet(v, st), ui.pushBtn);
  else if (tab === "secret") pane.push(...paneSecret(v));
  else if (tab === "grant") pane.push(...paneGrant(v));
  else pane.push(...paneLog(v));
  // Same nodes in the same order: leave the DOM alone, so a focused field (and the iOS keyboard)
  // survives a background view update.
  const cur = ui.main.children;
  if (pane.length !== cur.length || pane.some((n, i) => n !== cur[i])) ui.main.replaceChildren(...pane);
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
  ui.stSub.textContent = stateSub(v, st);
  ui.stIco.replaceChildren(icon(STATE_ICON[st]));
  tickHead();

  const btn = (text, cls, op, ico) => {
    const b = h("button", { class: `kg-btn kg-btn-ico ${cls}`, type: "button" }, ico ? icon(ico) : null, text);
    b.disabled = ui.busy;
    b.addEventListener("click", () => command(op, text));
    return b;
  };
  const acts = [];
  if (v) {
    if (st === "session") acts.push(btn("Kết thúc phiên", "wide", "session-end"), btn("Khóa", "danger", "lock", "lock"));
    else if (st === "unlocked") acts.push(btn("Mở phiên làm việc", "primary wide", "session-start", "bolt"), btn("Khóa", "danger", "lock", "lock"));
    else acts.push(btn("Mở khóa + mở phiên", "primary wide", "session-start", "unlock"));
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
    return [emptyState("duyet", st === "session" ? "ok" : st === "unlocked" ? "acc" : "", "Không có yêu cầu chờ", sub)];
  }
  const out = [h("div", { class: "kg-hrow" }, h("div", { class: "kg-title" }, "Chờ duyệt", h("span", { class: "kg-title-n" }, String(list.length))))];
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
function ttlPct(p) {
  const span = p.exp - p.created;
  return span > 0 ? Math.max(0, Math.min(100, ((p.exp - Date.now() / 1000) / span) * 100)) : 0;
}
function tickCards() {
  for (const c of cards.values()) {
    if (!c.meta) continue;
    c.meta.textContent = metaText(c.p);
    c.bar.style.width = ttlPct(c.p).toFixed(1) + "%"; // CSSOM, not a style attribute: allowed by the CSP
  }
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
  const node = h("div", { class: p.prod ? "kg-req is-prod" : "kg-req" });
  const meta = h("div", { class: "kg-meta" }, metaText(p));
  const bar = h("div");
  bar.style.width = ttlPct(p).toFixed(1) + "%";
  const c = { node, p, meta, bar, from };
  const doneText = decided.get(key);
  if (doneText) {
    showDone(c, doneText);
    return c;
  }
  const kids = [
    h("div", { class: "kg-req-top" },
      tile(OP_ICON[p.op] ?? "key", p.prod ? "bad" : "warn"),
      h("div", { class: "kg-req-head" }, h("div", { class: "kg-req-op" }, opTitle(p)), meta),
      p.prod ? chip("PROD", "bad") : null),
    p.secrets.length ? h("div", { class: "kg-req-secs" }, p.secrets.map((s) => chip(s, "", "kg-chip-mono"))) : null,
    h("div", { class: "kg-code" }, p.command),
    h("div", { class: "kg-ttl", "aria-hidden": "true" }, bar),
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
  const mk = (text, cls, choice, ico) => {
    const b = h("button", { class: cls, type: "button" }, ico ? icon(ico) : null, text);
    b.addEventListener("click", () => decide(c, choice, btns, err));
    btns.push(b);
    return b;
  };
  const row = h("div", { class: "kg-req-btns" });
  if (p.choices.includes("deny")) row.append(mk("Từ chối", "kg-btn danger", "deny"));
  if (p.choices.includes("allow")) row.append(mk("Cho phép", "kg-btn kg-btn-ico primary wide", "allow", "check"));
  kids.push(row);
  if (p.op === "grant") kids.push(h("div", { class: "kg-meta kg-mt6" }, "Cho phép: nhớ đến khi thu hồi, lần sau không hỏi lại cặp secret–lệnh này."));
  if (p.choices.includes("session")) kids.push(mk("Cho phép và mở phiên làm việc (không hỏi gì nữa)", "kg-more kg-req-alt", "session"));
  kids.push(err);
  node.replaceChildren(...kids.flat().filter(Boolean));
  return c;
}

function showDone(c, text) {
  c.node.className = "kg-req done";
  c.meta = null;
  const denied = text.startsWith("Đã từ chối");
  c.node.replaceChildren(h("div", { class: "kg-req-top" },
    tile(denied ? "x" : "check", denied ? "bad" : "ok"),
    h("div", { class: "kg-req-head" }, h("div", { class: "kg-req-op" }, opTitle(c.p)), h("div", { class: "kg-meta" }, text))));
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

function secretRow(s, prefix) {
  const env = envOf(s);
  const name = prefix && s.name.startsWith(prefix + "/")
    ? [h("span", { class: "kg-dim" }, prefix + "/"), s.name.slice(prefix.length + 1)]
    : s.name;
  return h("div", { class: "kg-item" },
    tile(KIND_ICON[s.kind] ?? "env", env === "prod" ? "bad" : ""),
    h("div", { class: "kg-item-main" },
      h("div", { class: "kg-item-name kg-mono" }, name),
      h("div", { class: "kg-item-sub" }, chip(env, ENV_TONE[env]), h("span", null, s.kind), h("span", { class: "kg-sep" }, lastUsed(s.last_used)))),
    s.conflict ? chip("Xung đột", "bad") : null);
}
function renderSecretList() {
  const v = current();
  const all = v?.secrets ?? [];
  const q = ui.secretFilter.value.trim().toLowerCase();
  const counts = { all: all.length, dev: 0, test: 0, prod: 0 };
  for (const s of all) counts[envOf(s)] = (counts[envOf(s)] ?? 0) + 1;
  if (ui.secretEnv !== "all" && !counts[ui.secretEnv]) ui.secretEnv = "all";
  ui.secretChips.replaceChildren(...[["all", "Tất cả"], ["dev", "dev"], ["test", "test"], ["prod", "prod"]]
    .filter(([k]) => k === "all" || counts[k])
    .map(([k, t]) => {
      const b = h("button", { type: "button", class: k === "prod" ? "kg-fchip is-prod" : "kg-fchip", "aria-pressed": String(ui.secretEnv === k) },
        t, h("span", { class: "kg-fchip-n" }, String(counts[k])));
      b.addEventListener("click", () => {
        ui.secretEnv = k;
        renderSecretList();
      });
      return b;
    }));
  const rows = all.filter((s) => (ui.secretEnv === "all" || envOf(s) === ui.secretEnv) && (!q || s.name.toLowerCase().includes(q)));
  ui.secretCount.textContent = rows.length === all.length ? String(all.length) : `${rows.length}/${all.length}`;
  const byName = (a, b) => a.name.localeCompare(b.name);
  const groups = []; // [label, prefix, rows]
  const sort = ui.secretSort.value;
  if (sort === "recent") {
    groups.push(["", "", rows.sort((a, b) => (b.last_used || 0) - (a.last_used || 0) || byName(a, b))]);
  } else if (sort === "env") {
    for (const e of ["prod", "test", "dev"]) {
      const g = rows.filter((s) => envOf(s) === e).sort(byName);
      if (g.length) groups.push([e.toUpperCase(), "", g]);
    }
    const other = rows.filter((s) => !["prod", "test", "dev"].includes(envOf(s))).sort(byName);
    if (other.length) groups.push(["Khác", "", other]);
  } else {
    const m = new Map();
    for (const s of rows.sort(byName)) {
      const i = s.name.indexOf("/");
      const p = i > 0 ? s.name.slice(0, i) : "";
      if (!m.has(p)) m.set(p, []);
      m.get(p).push(s);
    }
    for (const [p, g] of [...m].sort(([a], [b]) => (a === "") - (b === "") || a.localeCompare(b))) groups.push([p || "Không nhóm", p, g]);
  }
  const kids = [ui.flash ? h("div", { class: "kg-ok" }, icon("check"), ui.flash) : null];
  for (const [label, prefix, g] of groups) {
    if (label) kids.push(section(label, g.length));
    kids.push(h("div", { class: label ? "kg-group" : "kg-group kg-mt6" }, g.map((s) => secretRow(s, prefix))));
  }
  if (rows.length === 0) kids.push(emptyState("search", "", "Không có secret nào khớp", "Đổi từ khóa hoặc bộ lọc môi trường."));
  kids.push(h("p", { class: "kg-note kg-center" }, "Chỉ có tên và thông tin mô tả. Giá trị không bao giờ rời laptop."));
  ui.secretList.replaceChildren(...kids.filter(Boolean));
}
function paneSecret(v) {
  if (!v || !v.unlocked) {
    adding = false;
    return [emptyState("lock", "", "Vault đang khóa", "Mở khóa để xem và thêm secret.")];
  }
  if (adding) return paneAdd(v);
  renderSecretList();
  return [ui.secretHead, ui.secretSearch, ui.secretTools, ui.secretList];
}

// ---- tab Grant ----

function grantItem(g) {
  const b = h("button", { class: "kg-pill t-bad", type: "button" }, "Thu hồi");
  b.addEventListener("click", () => revoke(b, { secret: g.secret, pattern: g.pattern, path: g.path }));
  const byTone = g.approval === "session" || g.by === "session" ? "ok" : (g.by ?? "").startsWith("remote:") ? "acc" : "";
  const exp = g.expires ? chip(`hết hạn ${stamp(parseTime(g.expires))}`, "warn") : chip("không hết hạn");
  return h("div", { class: "kg-item top" },
    tile("key", isProdName(g.secret) ? "bad" : "acc"),
    h("div", { class: "kg-item-main" },
      h("div", { class: "kg-item-name kg-mono" }, g.secret),
      h("div", { class: "kg-pattern" }, g.pattern),
      g.dir ? h("div", { class: "kg-item-sub" }, icon("folder", "kg-ico-s"), h("span", { class: "kg-mono kg-break" }, g.dir)) : null,
      h("div", { class: "kg-item-sub" }, chip(grantBy(g), byTone), exp, h("span", null, stamp(parseTime(g.at))))),
    b);
}
function paneGrant(v) {
  const gs = [...(v?.grants ?? [])];
  ui.grantCount.textContent = String(gs.length);
  if (gs.length === 0) return [ui.grantHead, emptyState("grant", "", "Chưa có grant nào", "Bấm Cho phép ở tab Duyệt sẽ nhớ đúng cặp secret–lệnh đó tới khi thu hồi.")];
  const at = (g) => parseTime(g.at);
  const sort = ui.grantSort.value;
  if (sort === "secret") gs.sort((a, b) => a.secret.localeCompare(b.secret) || at(b) - at(a));
  else if (sort === "exp") gs.sort((a, b) => (a.expires ? parseTime(a.expires) : Infinity) - (b.expires ? parseTime(b.expires) : Infinity) || at(b) - at(a));
  else gs.sort((a, b) => at(b) - at(a));
  const all = h("button", { class: "kg-btn danger kg-full kg-btn-ico", type: "button" }, icon("unlink"), "Thu hồi tất cả");
  all.addEventListener("click", () => revoke(all, { all: true }));
  return [ui.grantHead, h("div", { class: "kg-group" }, gs.map(grantItem)), h("div", { class: "kg-mt" }, all)];
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

const EVENTS = {
  run: ["Chạy lệnh", "play", "acc"],
  "run-start": ["Bắt đầu chạy", "play", "acc"],
  grant: ["Cấp quyền", "check", "ok"],
  deny: ["Từ chối", "x", "bad"],
  set: ["Lưu secret", "plus", "ok"],
  import: ["Nhập từ file", "doc", "ok"],
  delete: ["Xóa secret", "trash", "bad"],
  compare: ["So sánh file", "doc", ""],
  session: ["Phiên làm việc", "bolt", "ok"],
  same: ["So khớp giá trị", "doc", ""],
  copy: ["Sao chép secret", "doc", ""],
  policy: ["Áp dụng policy", "doc", "warn"],
  reveal: ["Xem giá trị", "eye", "warn"],
  "grant-revoke": ["Thu hồi grant", "unlink", "warn"],
  "device-add": ["Thêm thiết bị", "phone", "ok"],
  "device-revoke": ["Thu hồi thiết bị", "phone", "bad"],
};
const logClass = (e) => (e === "run" || e === "run-start" ? "run" : e === "deny" ? "deny" : "change");
function logItem(a) {
  const [title, ico, t] = EVENTS[a.event] ?? [a.event, "doc", ""];
  const failed = a.event === "run" && a.exit !== 0;
  return h("div", { class: "kg-item top" },
    tile(ico, failed ? "bad" : t),
    h("div", { class: "kg-item-main" },
      h("div", { class: "kg-item-name" }, title),
      a.secret ? h("div", { class: "kg-item-sec kg-mono" }, a.secret) : null,
      h("div", { class: "kg-item-sub" },
        a.approval ? chip(approvalLabel(a.approval), a.approval === "session" ? "ok" : a.approval.startsWith("remote:") ? "acc" : "") : null,
        a.agent ? h("span", null, a.agent) : null)),
    h("div", { class: "kg-item-end" },
      h("time", null, hhmm(a.time * 1000)),
      a.event === "run" ? chip(`exit ${a.exit}`, failed ? "bad" : "ok") : null));
}
function paneLog(v) {
  const f = ui.logSeg.value;
  const rows = [...(v?.audit ?? [])].filter((a) => f === "all" || logClass(a.event) === f).sort((a, b) => b.time - a.time);
  const out = [ui.logHead, ui.logSeg.node];
  if (rows.length === 0) {
    out.push(emptyState("log", "", "Chưa có dòng nhật ký", f === "all" ? "Mọi lần cấp, chạy, từ chối trên laptop sẽ hiện ở đây." : "Không có dòng nào thuộc loại này."));
    return out;
  }
  let day = null, group = null;
  for (const a of rows) {
    const d = dayLabel(a.time * 1000);
    if (d !== day) {
      day = d;
      group = h("div", { class: "kg-group" });
      out.push(section(d), group);
    }
    group.append(logItem(a));
  }
  out.push(h("p", { class: "kg-note kg-center" }, "50 dòng gần nhất của nhật ký trên laptop."));
  return out;
}

// ---- Secret › Thêm secret ----

function buildForm() {
  const inp = (label, attrs) => h("input", { type: "text", autocomplete: "off", autocapitalize: "off", spellcheck: "false", "aria-label": label, ...attrs });
  const field = (text, el, ...extra) => h("div", { class: "kg-field" }, lab(text, el), el, ...extra);
  const f = {
    back: h("button", { class: "kg-back", type: "button" }, icon("back"), "Secret"),
    name: inp("Tên", { placeholder: "vd: app/test-db-password" }),
    env: segmented("Môi trường", [["dev", "dev"], ["test", "test"], ["prod", "prod", "is-prod"]], "dev", () => checkProd()),
    kind: h("select", { "aria-label": "Loại" }, [["env", "env: biến môi trường"], ["file", "file: file tạm"], ["template", "template: thay vào file"], ["oracle-wallet", "oracle-wallet: wallet SQLcl"]].map(([v, t]) => h("option", { value: v }, t))),
    envName: inp("Tên biến môi trường", { placeholder: "DB_PASSWORD" }),
    tns: inp("TNS alias", {}),
    user: inp("User", {}),
    value: h("input", { type: "password", placeholder: "gõ hoặc dán", "aria-label": "Giá trị", autocomplete: "off", autocapitalize: "off" }),
    btn: h("button", { class: "kg-btn primary kg-full kg-btn-ico", type: "button" }, icon("lock"), "Lưu vào vault trên laptop"),
    err: h("div", { class: "kg-warn kg-mt", hidden: true }),
    prodNote: h("div", { class: "kg-hint t-bad", hidden: true }, icon("alert", "kg-ico-s"), "Secret này sẽ được coi là PROD (theo môi trường hoặc đoạn prod/prd trong tên)."),
    note: h("p", { class: "kg-note kg-center" }),
    wallet: h("div", { class: "kg-field two", hidden: true }),
  };
  const checkProd = () => (f.prodNote.hidden = !(f.env.value === "prod" || isProdName(f.name.value)));
  f.name.addEventListener("input", checkProd);
  f.wallet.append(h("div", null, lab("TNS alias", f.tns), f.tns), h("div", null, lab("User", f.user), f.user));
  f.kind.addEventListener("change", () => (f.wallet.hidden = f.kind.value !== "oracle-wallet"));
  f.btn.addEventListener("click", submitSecret);
  f.back.addEventListener("click", () => {
    adding = false;
    renderAll();
  });
  const envLabel = h("div", { class: "kg-lab" }, "Môi trường");
  f.head = h("div", { class: "kg-subhead" }, f.back, h("div", { class: "kg-title" }, "Thêm secret"));
  f.node = h("form", { class: "kg-form", onsubmit: (e) => e.preventDefault() },
    h("div", { class: "kg-fsec" }, "Định danh"),
    h("div", { class: "kg-group kg-fgroup" },
      field("Tên", f.name, h("div", { class: "kg-fhint" }, "Dạng <repo hoặc hệ thống>/<môi trường>/<tên>. Tên đã có thì laptop từ chối: ghi đè chỉ làm tại máy.")),
      h("div", { class: "kg-field" }, envLabel, f.env.node, f.prodNote)),
    h("div", { class: "kg-fsec" }, "Cách cấp cho chương trình"),
    h("div", { class: "kg-group kg-fgroup" },
      field("Loại", f.kind),
      field("Tên biến môi trường", f.envName),
      f.wallet),
    h("div", { class: "kg-fsec" }, "Giá trị"),
    h("div", { class: "kg-group kg-fgroup" }, field("Giá trị", f.value)),
    h("div", { class: "kg-mt" }, f.btn), f.err, f.note);
  f.kind.dispatchEvent(new Event("change"));
  return f;
}

function paneAdd(v) {
  ui.form ??= buildForm();
  const f = ui.form;
  if (!f.sending) f.btn.disabled = false;
  f.note.textContent = `Giá trị được mã hóa cho riêng ${v.label} trước khi rời điện thoại. Máy chủ chỉ chuyển bản mã.`;
  return [f.head, f.node];
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
  f.btn.lastChild.textContent = "Đang gửi…";
  const args = {
    name, kind: f.kind.value, env: f.env.value, env_name: f.envName.value.trim(),
    tns_alias: f.kind.value === "oracle-wallet" ? f.tns.value.trim() : "",
    user: f.kind.value === "oracle-wallet" ? f.user.value.trim() : "",
    desc: "", value,
  };
  f.value.value = ""; // the value never stays in the form
  try {
    const cid = await sendCommand(sel, "set", args);
    const r = await waitResult(cid, 45000);
    if (!r) throw new Error("Laptop chưa trả lời. Kiểm tra lại sau.");
    if (!r.ok) throw new Error(r.msg || "Laptop từ chối");
    f.sending = false;
    f.btn.lastChild.textContent = "Lưu vào vault trên laptop";
    f.name.value = "";
    f.envName.value = "";
    f.prodNote.hidden = f.env.value !== "prod";
    ui.flash = `Đã lưu: ${name}`;
    adding = false;
    renderAll();
    setTimeout(() => {
      ui.flash = "";
      renderSecretList();
    }, 5000);
  } catch (e) {
    f.err.textContent = e.message;
    f.err.hidden = false;
    f.btn.lastChild.textContent = "Lưu vào vault trên laptop";
    setTimeout(() => {
      f.sending = false;
      f.btn.disabled = !current()?.unlocked;
    }, 1500);
  }
}

// ---------- boot ----------

async function startMain(kv, xKey) {
  sess = { vault: kv.vault, pin: kv.pin, dev: kv.dev, label: kv.label, edKey: kv.edKey, xKey, edPub: kv.edPub, xPub: kv.xPub, membersMark: kv.membersCount ? { count: kv.membersCount, head: kv.membersHead } : null };
  sel = kv.sel ?? null;
  buildShell();
  if (["name", "recent", "env"].includes(kv.secretSort)) ui.secretSort.value = kv.secretSort;
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
    h("p", null, "Khóa riêng của điện thoại không đọc lại được (bản cũ của app lưu khóa theo cách iOS không giữ). Bấm Ghép lại để tạo khóa mới, rồi trên laptop mở lại Ghép điện thoại… (khay) hoặc kg device pair."),
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
    return pairing({ words: kv.words });
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
